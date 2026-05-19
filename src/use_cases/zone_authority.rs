use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CAA, CNAME, MX, NAPTR, NS, PTR, SOA, SRV, TLSA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use hickory_proto::rr::rdata::caa::KeyValue;
use hickory_proto::rr::rdata::tlsa::{CertUsage, Matching, Selector};

use crate::use_cases::upstream_resolver::{UpstreamResolveError, UpstreamResolver};

const DEFAULT_URL_CHECK_INTERVAL_SECS: u64 = 15 * 60;
const HTTP_TIMEOUT_SECS: u64 = 30;
const MAX_ZONE_SOURCE_BYTES: usize = 2 * 1024 * 1024;

/// A single DNS record from a zone, suitable for search results.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ZoneRecord {
    pub name: String,
    pub record_type: String,
    pub ttl: u32,
    pub data: String,
    pub zone: String,
}

/// Trait for zone resolvers that support record introspection and search.
pub trait ZoneSearchable: Send + Sync {
    fn zone_name(&self) -> String;
    fn record_count(&self) -> usize;
    fn list_records(&self, record_type: Option<&str>) -> Vec<ZoneRecord>;
    fn search_records(
        &self,
        query: &str,
        record_type: Option<&str>,
        limit: usize,
    ) -> Vec<(ZoneRecord, i64)>;
}

#[derive(Debug, Clone)]
enum ZoneSource {
    File(String),
    Url(String),
}

/// Authentication credentials for HTTP(S) zone sources.
#[derive(Debug, Clone)]
pub enum ZoneSourceAuth {
    Bearer(String),
    Basic { username: String, password: String },
}

#[derive(Debug, Clone)]
struct ZoneSnapshot {
    zone: String,
    records_by_name: HashMap<String, Vec<Record>>,
    soa: Option<Record>,
}

#[derive(Debug)]
pub struct ZoneAuthorityResolver {
    snapshot: Arc<RwLock<ZoneSnapshot>>,
}

impl ZoneAuthorityResolver {
    pub fn from_source(
        zone: &str,
        source: &str,
        check_interval: Option<Duration>,
        auth: Option<ZoneSourceAuth>,
    ) -> Result<Self> {
        let source = parse_zone_source(source)?;
        let initial = load_snapshot(zone, &source, &auth)?;
        let snapshot = Arc::new(RwLock::new(initial));

        let resolver = Self {
            snapshot: Arc::clone(&snapshot),
        };

        if let ZoneSource::Url(url) = source {
            let interval =
                check_interval.unwrap_or(Duration::from_secs(DEFAULT_URL_CHECK_INTERVAL_SECS));
            spawn_periodic_url_refresh(zone.to_string(), url, interval, snapshot, auth);
        }

        Ok(resolver)
    }
}

#[async_trait]
impl UpstreamResolver for ZoneAuthorityResolver {
    async fn resolve(&self, query: Vec<u8>) -> Result<Vec<u8>, UpstreamResolveError> {
        let request = Message::from_vec(&query)
            .map_err(|e| UpstreamResolveError::Protocol(format!("invalid DNS query: {e}")))?;

        let question = request.queries.first().ok_or_else(|| {
            UpstreamResolveError::Protocol("DNS query has no question".to_string())
        })?;

        let query_name = normalize_name(&question.name().to_ascii())
            .ok_or_else(|| UpstreamResolveError::Protocol("invalid query name".to_string()))?;

        let snapshot = self
            .snapshot
            .read()
            .map_err(|_| UpstreamResolveError::Protocol("zone snapshot lock poisoned".to_string()))?
            .clone();

        let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
        response.metadata.recursion_desired = request.recursion_desired;
        response.metadata.recursion_available = false;
        response.metadata.authoritative = true;
        response.add_query(question.clone());

        if !domain_matches_zone(&query_name, &snapshot.zone) {
            response.metadata.response_code = ResponseCode::Refused;
            return response.to_vec().map_err(|e| {
                UpstreamResolveError::Protocol(format!("failed to encode refused response: {e}"))
            });
        }

        if let Some(records) = snapshot.records_by_name.get(&query_name) {
            let mut answers = filter_answers(records, question.query_type());
            if answers.is_empty() && question.query_type() != RecordType::CNAME {
                answers = filter_answers(records, RecordType::CNAME);
            }

            if answers.is_empty() {
                response.metadata.response_code = ResponseCode::NoError;
                if let Some(soa) = &snapshot.soa {
                    response.add_authority(soa.clone());
                }
            } else {
                let ns_glue = collect_ns_glue_records(&answers, &snapshot.records_by_name);
                response.metadata.response_code = ResponseCode::NoError;
                for answer in answers {
                    response.add_answer(answer);
                }
                for glue in ns_glue {
                    response.add_additional(glue);
                }
            }
        } else {
            response.metadata.response_code = ResponseCode::NXDomain;
            if let Some(soa) = &snapshot.soa {
                response.add_authority(soa.clone());
            }
        }

        response.to_vec().map_err(|e| {
            UpstreamResolveError::Protocol(format!("failed to encode DNS response: {e}"))
        })
    }
}

impl ZoneSearchable for ZoneAuthorityResolver {
    fn zone_name(&self) -> String {
        self.snapshot
            .read()
            .map(|s| s.zone.clone())
            .unwrap_or_default()
    }

    fn record_count(&self) -> usize {
        self.snapshot
            .read()
            .map(|s| s.records_by_name.values().map(|v| v.len()).sum())
            .unwrap_or(0)
    }

    fn list_records(&self, record_type: Option<&str>) -> Vec<ZoneRecord> {
        let snapshot = match self.snapshot.read() {
            Ok(s) => s.clone(),
            Err(_) => return Vec::new(),
        };
        let type_filter = record_type.and_then(parse_record_type_filter);
        snapshot_to_zone_records(&snapshot, type_filter.as_ref())
    }

    fn search_records(
        &self,
        query: &str,
        record_type: Option<&str>,
        limit: usize,
    ) -> Vec<(ZoneRecord, i64)> {
        use fuzzy_matcher::skim::SkimMatcherV2;
        use fuzzy_matcher::FuzzyMatcher;

        let snapshot = match self.snapshot.read() {
            Ok(s) => s.clone(),
            Err(_) => return Vec::new(),
        };
        let type_filter = record_type.and_then(parse_record_type_filter);
        let matcher = SkimMatcherV2::default();
        let zone = &snapshot.zone;

        let mut scored: Vec<(ZoneRecord, i64)> = snapshot
            .records_by_name
            .iter()
            .flat_map(|(name, records)| {
                let score = matcher.fuzzy_match(name, query);
                records
                    .iter()
                    .filter(|r| match &type_filter {
                        Some(rt) => r.record_type() == *rt,
                        None => true,
                    })
                    .filter_map(move |record| {
                        score.map(|s| (record_to_zone_record(record, name, zone), s))
                    })
            })
            .collect();

        scored.sort_by_key(|b| std::cmp::Reverse(b.1));
        scored.truncate(limit);
        scored
    }
}

fn parse_record_type_filter(s: &str) -> Option<RecordType> {
    match s.to_uppercase().as_str() {
        "A" => Some(RecordType::A),
        "AAAA" => Some(RecordType::AAAA),
        "NS" => Some(RecordType::NS),
        "CNAME" => Some(RecordType::CNAME),
        "PTR" => Some(RecordType::PTR),
        "MX" => Some(RecordType::MX),
        "TXT" => Some(RecordType::TXT),
        "SOA" => Some(RecordType::SOA),
        "SRV" => Some(RecordType::SRV),
        "CAA" => Some(RecordType::CAA),
        "TLSA" => Some(RecordType::TLSA),
        "NAPTR" => Some(RecordType::NAPTR),
        _ => None,
    }
}

fn snapshot_to_zone_records(
    snapshot: &ZoneSnapshot,
    type_filter: Option<&RecordType>,
) -> Vec<ZoneRecord> {
    snapshot
        .records_by_name
        .iter()
        .flat_map(|(name, records)| {
            records
                .iter()
                .filter(|r| match type_filter {
                    Some(rt) => r.record_type() == *rt,
                    None => true,
                })
                .map(move |record| record_to_zone_record(record, name, &snapshot.zone))
        })
        .collect()
}

fn record_to_zone_record(record: &Record, name: &str, zone: &str) -> ZoneRecord {
    ZoneRecord {
        name: name.to_string(),
        record_type: record.record_type().to_string(),
        ttl: record.ttl,
        data: rdata_display(&record.data),
        zone: zone.to_string(),
    }
}

fn rdata_display(rdata: &RData) -> String {
    match rdata {
        RData::A(a) => a.0.to_string(),
        RData::AAAA(aaaa) => aaaa.0.to_string(),
        RData::NS(ns) => ns.0.to_string(),
        RData::CNAME(cname) => cname.0.to_string(),
        RData::PTR(ptr) => ptr.0.to_string(),
        RData::MX(mx) => format!("{} {}", mx.preference, mx.exchange),
        RData::TXT(txt) => String::from_utf8_lossy(
            &txt.txt_data
                .iter()
                .flat_map(|s| s.iter().copied())
                .collect::<Vec<u8>>(),
        )
        .into_owned(),
        RData::SOA(soa) => format!(
            "{} {} {} {} {} {} {}",
            soa.mname, soa.rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum
        ),
        RData::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority, srv.weight, srv.port, srv.target
        ),
        _ => format!("{rdata:?}"),
    }
}

fn filter_answers(records: &[Record], query_type: RecordType) -> Vec<Record> {
    if query_type == RecordType::ANY {
        return records.to_vec();
    }

    records
        .iter()
        .filter(|record| record.record_type() == query_type)
        .cloned()
        .collect()
}

fn collect_ns_glue_records(
    answers: &[Record],
    records_by_name: &HashMap<String, Vec<Record>>,
) -> Vec<Record> {
    let mut glue = Vec::new();

    for answer in answers {
        if answer.record_type() != RecordType::NS {
            continue;
        }

        let RData::NS(target) = &answer.data else {
            continue;
        };

        let Some(target_key) = normalize_name(&target.0.to_ascii()) else {
            continue;
        };

        let Some(target_records) = records_by_name.get(&target_key) else {
            continue;
        };

        for target_record in target_records {
            if target_record.record_type() != RecordType::A
                && target_record.record_type() != RecordType::AAAA
            {
                continue;
            }

            if !glue.iter().any(|existing| existing == target_record) {
                glue.push(target_record.clone());
            }
        }
    }

    glue
}

fn spawn_periodic_url_refresh(
    zone: String,
    url: String,
    interval: Duration,
    snapshot: Arc<RwLock<ZoneSnapshot>>,
    auth: Option<ZoneSourceAuth>,
) {
    if tokio::runtime::Handle::try_current().is_err() {
        tracing::warn!(zone = %zone, source = %url, "no active tokio runtime, URL zone_source refresh disabled");
        return;
    }

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let source = ZoneSource::Url(url.clone());
            let loaded = tokio::task::spawn_blocking({
                let zone = zone.clone();
                let source = source.clone();
                let auth = auth.clone();
                move || load_snapshot(&zone, &source, &auth)
            })
            .await;

            match loaded {
                Ok(Ok(new_snapshot)) => {
                    if let Ok(mut guard) = snapshot.write() {
                        *guard = new_snapshot;
                        tracing::info!(zone = %zone, source = %url, "refreshed URL-backed zone_source");
                    }
                }
                Ok(Err(error)) => {
                    tracing::warn!(zone = %zone, source = %url, error = %error, "zone_source refresh failed, keeping last good snapshot");
                }
                Err(error) => {
                    tracing::warn!(zone = %zone, source = %url, error = %error, "zone_source refresh task failed, keeping last good snapshot");
                }
            }
        }
    });
}

fn parse_zone_source(source: &str) -> Result<ZoneSource> {
    let source = source.trim();
    if source.starts_with("http://") || source.starts_with("https://") {
        return Ok(ZoneSource::Url(source.to_string()));
    }

    if let Some(path) = source.strip_prefix("file://") {
        return Ok(ZoneSource::File(path.to_string()));
    }

    if source.contains("://") {
        bail!("unsupported zone source scheme in '{source}'; use file://, http://, or https://");
    }

    Ok(ZoneSource::File(source.to_string()))
}

fn load_snapshot(
    expected_zone: &str,
    source: &ZoneSource,
    auth: &Option<ZoneSourceAuth>,
) -> Result<ZoneSnapshot> {
    let content = load_source_content(source, auth)?;
    let document: ZoneJsonDocument = serde_json::from_str(&content).with_context(|| {
        format!(
            "failed to parse JSON zone document from {}",
            source_label(source)
        )
    })?;

    let json_zone =
        normalize_name(&document.zone).ok_or_else(|| anyhow!("JSON zone must not be empty"))?;
    let expected_zone = normalize_name(expected_zone)
        .ok_or_else(|| anyhow!("configured zone must not be empty"))?;

    if json_zone != expected_zone {
        bail!(
            "zone mismatch: config zone '{}' differs from JSON zone '{}'",
            expected_zone,
            json_zone
        );
    }

    let mut records_by_name: HashMap<String, Vec<Record>> = HashMap::new();
    let mut soa: Option<Record> = None;
    let ttl_default = document.ttl_default.unwrap_or(3600);

    for entry in &document.records {
        let name_key = resolve_record_name(&json_zone, &entry.name)?;
        let name = fqdn_to_name(&name_key)?;
        let ttl = entry.ttl.unwrap_or(ttl_default);
        let record = parse_record(entry, name, ttl)?;

        if record.record_type() == RecordType::SOA && name_key == json_zone && soa.is_none() {
            soa = Some(record.clone());
        }

        records_by_name.entry(name_key).or_default().push(record);
    }

    ensure_default_apex_ns(&json_zone, ttl_default, &mut records_by_name)?;
    if soa.is_none() {
        soa = Some(build_default_soa_record(
            &document,
            &json_zone,
            ttl_default,
        )?);
        if let Some(soa_record) = &soa {
            records_by_name
                .entry(json_zone.clone())
                .or_default()
                .push(soa_record.clone());
        }
    }

    Ok(ZoneSnapshot {
        zone: json_zone,
        records_by_name,
        soa,
    })
}

fn ensure_default_apex_ns(
    zone: &str,
    ttl_default: u32,
    records_by_name: &mut HashMap<String, Vec<Record>>,
) -> Result<()> {
    let has_apex_ns = records_by_name.get(zone).is_some_and(|records| {
        records
            .iter()
            .any(|record| record.record_type() == RecordType::NS)
    });
    if has_apex_ns {
        return Ok(());
    }

    let ns_target = fqdn_to_name(&format!("ns1.{zone}"))?;
    let zone_name = fqdn_to_name(zone)?;
    let ns_record = Record::from_rdata(zone_name, ttl_default, RData::NS(NS(ns_target)));
    records_by_name
        .entry(zone.to_string())
        .or_default()
        .push(ns_record);
    Ok(())
}

fn build_default_soa_record(
    document: &ZoneJsonDocument,
    zone: &str,
    ttl_default: u32,
) -> Result<Record> {
    let zone_name = fqdn_to_name(zone)?;
    let mname = fqdn_to_name(&format!("ns1.{zone}"))?;
    let rname = fqdn_to_name(&format!("hostmaster.{zone}"))?;
    let serial = parse_serial_or_default(document.serial.as_deref(), 1);
    let refresh = 3600;
    let retry = 900;
    let expire = 604800;
    let minimum = 300;
    Ok(Record::from_rdata(
        zone_name,
        ttl_default,
        RData::SOA(SOA::new(
            mname, rname, serial, refresh, retry, expire, minimum,
        )),
    ))
}

fn parse_serial_or_default(value: Option<&str>, default: u32) -> u32 {
    value
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .unwrap_or(default)
}

fn source_label(source: &ZoneSource) -> &str {
    match source {
        ZoneSource::File(path) => path,
        ZoneSource::Url(url) => url,
    }
}

fn load_source_content(source: &ZoneSource, auth: &Option<ZoneSourceAuth>) -> Result<String> {
    match source {
        ZoneSource::File(path) => fs::read_to_string(path)
            .with_context(|| format!("failed to read zone_source file {path}")),
        ZoneSource::Url(url) => {
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
                .build()
                .context("failed to initialize HTTP client for zone_source")?;

            let mut request = client.get(url);

            if let Some(zone_auth) = auth {
                request = match zone_auth {
                    ZoneSourceAuth::Bearer(token) => request.bearer_auth(token),
                    ZoneSourceAuth::Basic { username, password } => {
                        request.basic_auth(username, Some(password))
                    }
                };
            }

            let response = request
                .send()
                .with_context(|| format!("failed to download zone_source from {url}"))?
                .error_for_status()
                .with_context(|| format!("zone_source returned non-success status: {url}"))?;

            if let Some(content_len) = response.content_length() {
                if content_len as usize > MAX_ZONE_SOURCE_BYTES {
                    bail!(
                        "zone_source response too large: {} bytes exceeds limit {}",
                        content_len,
                        MAX_ZONE_SOURCE_BYTES
                    );
                }
            }

            let body = response
                .text()
                .with_context(|| format!("failed reading zone_source response body from {url}"))?;
            if body.len() > MAX_ZONE_SOURCE_BYTES {
                bail!(
                    "zone_source response too large: {} bytes exceeds limit {}",
                    body.len(),
                    MAX_ZONE_SOURCE_BYTES
                );
            }

            Ok(body)
        }
    }
}

fn parse_record(entry: &ZoneJsonRecord, name: Name, ttl: u32) -> Result<Record> {
    let rtype = entry.record_type.trim().to_ascii_uppercase();
    let rdata = match rtype.as_str() {
        "A" => {
            let address = get_str(&entry.data, "address")?
                .parse()
                .with_context(|| format!("invalid A address in record '{}'", entry.name))?;
            RData::A(A(address))
        }
        "AAAA" => {
            let address = get_str(&entry.data, "address")?
                .parse()
                .with_context(|| format!("invalid AAAA address in record '{}'", entry.name))?;
            RData::AAAA(AAAA(address))
        }
        "NS" => {
            let target = fqdn_to_name(get_str(&entry.data, "target")?)?;
            RData::NS(NS(target))
        }
        "CNAME" => {
            let target = fqdn_to_name(get_str(&entry.data, "target")?)?;
            RData::CNAME(CNAME(target))
        }
        "PTR" => {
            let target = fqdn_to_name(get_str(&entry.data, "target")?)?;
            RData::PTR(PTR(target))
        }
        "MX" => {
            let priority = get_u16(&entry.data, "priority")?;
            let exchange = fqdn_to_name(get_str(&entry.data, "exchange")?)?;
            RData::MX(MX::new(priority, exchange))
        }
        "TXT" => {
            let values = get_string_array(&entry.data, "values")?;
            RData::TXT(TXT::new(values))
        }
        "SOA" => {
            let mname = fqdn_to_name(get_str(&entry.data, "mname")?)?;
            let rname = fqdn_to_name(get_str(&entry.data, "rname")?)?;
            let serial = get_u32(&entry.data, "serial")?;
            let refresh = get_i32(&entry.data, "refresh")?;
            let retry = get_i32(&entry.data, "retry")?;
            let expire = get_i32(&entry.data, "expire")?;
            let minimum = get_u32(&entry.data, "minimum")?;
            RData::SOA(SOA::new(
                mname, rname, serial, refresh, retry, expire, minimum,
            ))
        }
        "SRV" => {
            let priority = get_u16(&entry.data, "priority")?;
            let weight = get_u16(&entry.data, "weight")?;
            let port = get_u16(&entry.data, "port")?;
            let target = fqdn_to_name(get_str(&entry.data, "target")?)?;
            RData::SRV(SRV::new(priority, weight, port, target))
        }
        "CAA" => {
            let flags_raw = get_u8(&entry.data, "flags")?;
            let issuer_critical = flags_raw & 0x80 != 0;
            let tag_raw = get_str(&entry.data, "tag")?.trim().to_ascii_lowercase();
            let value_raw = get_str(&entry.data, "value")?.trim();

            let caa = match tag_raw.as_str() {
                "issue" => {
                    let issuer_name = parse_issue_issuer_name(value_raw)?;
                    CAA::new_issue(issuer_critical, issuer_name, Vec::<KeyValue>::new())
                }
                "issuewild" => {
                    let issuer_name = parse_issue_issuer_name(value_raw)?;
                    CAA::new_issuewild(issuer_critical, issuer_name, Vec::<KeyValue>::new())
                }
                "iodef" => {
                    let url = Url::parse(value_raw)
                        .with_context(|| format!("invalid CAA iodef URL '{}'", value_raw))?;
                    CAA::new_iodef(issuer_critical, url)
                }
                other => {
                    let supported = "issue, issuewild, iodef";
                    bail!(
                        "unsupported CAA tag '{}'; supported tags are: {}",
                        other,
                        supported
                    );
                }
            };

            RData::CAA(caa)
        }
        "TLSA" => {
            let usage = CertUsage::from(get_u8(&entry.data, "usage")?);
            let selector = Selector::from(get_u8(&entry.data, "selector")?);
            let matching = Matching::from(get_u8(&entry.data, "matching_type")?);
            let certificate = get_str(&entry.data, "certificate")?;
            let cert_data = decode_hex(certificate).with_context(|| {
                format!("invalid TLSA certificate hex in record '{}'", entry.name)
            })?;
            RData::TLSA(TLSA::new(usage, selector, matching, cert_data))
        }
        "NAPTR" => {
            let order = get_u16(&entry.data, "order")?;
            let preference = get_u16(&entry.data, "preference")?;
            let flags = get_str(&entry.data, "flags")?
                .as_bytes()
                .to_vec()
                .into_boxed_slice();
            let service = get_str(&entry.data, "service")?
                .as_bytes()
                .to_vec()
                .into_boxed_slice();
            let regexp = get_str(&entry.data, "regexp")?
                .as_bytes()
                .to_vec()
                .into_boxed_slice();
            let replacement = fqdn_to_name(get_str(&entry.data, "replacement")?)?;
            RData::NAPTR(NAPTR::new(
                order,
                preference,
                flags,
                service,
                regexp,
                replacement,
            ))
        }
        other => {
            bail!("unsupported record type '{}'", other);
        }
    };

    Ok(Record::from_rdata(name, ttl, rdata))
}

fn resolve_record_name(zone: &str, label: &str) -> Result<String> {
    let label = label.trim();
    if label.is_empty() {
        bail!("record name must not be empty");
    }

    if label == "@" {
        return Ok(zone.to_string());
    }

    if label.ends_with('.') {
        return normalize_name(label)
            .ok_or_else(|| anyhow!("invalid absolute record name '{label}'"));
    }

    normalize_name(&format!("{label}.{zone}"))
        .ok_or_else(|| anyhow!("invalid record name '{label}'"))
}

fn normalize_name(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

fn fqdn_to_name(value: &str) -> Result<Name> {
    let normalized = normalize_name(value).ok_or_else(|| anyhow!("name must not be empty"))?;
    Name::from_ascii(format!("{normalized}."))
        .map_err(|e| anyhow!("invalid DNS name '{value}': {e}"))
}

fn domain_matches_zone(domain: &str, zone: &str) -> bool {
    domain == zone
        || domain
            .strip_suffix(zone)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn get_str<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing or invalid string field '{key}'"))
}

fn get_u16(value: &Value, key: &str) -> Result<u16> {
    let number = value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing or invalid integer field '{key}'"))?;
    u16::try_from(number).map_err(|_| anyhow!("field '{key}' out of range for u16"))
}

fn get_u8(value: &Value, key: &str) -> Result<u8> {
    let number = value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing or invalid integer field '{key}'"))?;
    u8::try_from(number).map_err(|_| anyhow!("field '{key}' out of range for u8"))
}

fn get_u32(value: &Value, key: &str) -> Result<u32> {
    let number = value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing or invalid integer field '{key}'"))?;
    u32::try_from(number).map_err(|_| anyhow!("field '{key}' out of range for u32"))
}

fn get_i32(value: &Value, key: &str) -> Result<i32> {
    let number = value
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("missing or invalid integer field '{key}'"))?;
    i32::try_from(number).map_err(|_| anyhow!("field '{key}' out of range for i32"))
}

fn get_string_array(value: &Value, key: &str) -> Result<Vec<String>> {
    let values = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("missing or invalid array field '{key}'"))?;

    values
        .iter()
        .map(|item| {
            item.as_str()
                .map(ToString::to_string)
                .ok_or_else(|| anyhow!("field '{key}' must only contain strings"))
        })
        .collect()
}

fn parse_issue_issuer_name(value: &str) -> Result<Option<Name>> {
    if value.is_empty() || value == ";" {
        return Ok(None);
    }

    Ok(Some(fqdn_to_name(value)?))
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    let cleaned = value.trim();
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }
    if !cleaned.len().is_multiple_of(2) {
        bail!("hex value has odd length");
    }

    let mut output = Vec::with_capacity(cleaned.len() / 2);
    for chunk in cleaned.as_bytes().chunks(2) {
        let pair =
            std::str::from_utf8(chunk).map_err(|_| anyhow!("hex contains non-utf8 bytes"))?;
        let byte = u8::from_str_radix(pair, 16)
            .map_err(|_| anyhow!("hex contains invalid digit pair '{}'", pair))?;
        output.push(byte);
    }

    Ok(output)
}

#[derive(Debug, Deserialize)]
struct ZoneJsonDocument {
    zone: String,
    ttl_default: Option<u32>,
    #[allow(dead_code)]
    serial: Option<String>,
    records: Vec<ZoneJsonRecord>,
}

#[derive(Debug, Deserialize)]
struct ZoneJsonRecord {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    ttl: Option<u32>,
    data: Value,
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use hickory_proto::op::Query;
    use hickory_proto::rr::{DNSClass, RecordType};

    use super::*;

    fn create_temp_zone_json(content: &str) -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "dns-filter-zone-authority-test-{}-{id}.json",
            std::process::id()
        ));
        fs::write(&path, content).expect("failed to write temporary zone source");
        path.to_string_lossy().to_string()
    }

    fn make_query(name: &str, query_type: RecordType) -> Vec<u8> {
        let mut message = Message::new(42, MessageType::Query, OpCode::Query);
        let mut query = Query::new();
        query.set_name(Name::from_ascii(name).expect("valid query name"));
        query.set_query_type(query_type);
        query.set_query_class(DNSClass::IN);
        message.add_query(query);
        message
            .to_vec()
            .expect("query serialization should succeed")
    }

    #[test]
    fn normalize_name_trims_trailing_dot() {
        assert_eq!(
            normalize_name("Example.COM."),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn parse_zone_source_file() {
        let source = parse_zone_source("/tmp/zone.json").expect("file source should parse");
        assert!(matches!(source, ZoneSource::File(_)));
    }

    #[test]
    fn parse_zone_source_url() {
        let source =
            parse_zone_source("https://example.com/zone.json").expect("url source should parse");
        assert!(matches!(source, ZoneSource::Url(_)));
    }

    #[tokio::test]
    async fn ns_answers_include_glue_additionals() {
        let zone_file = create_temp_zone_json(
            r#"{
                "zone":"example.com",
                "ttl_default":3600,
                "records":[
                    {"name":"@","type":"NS","ttl":3600,"data":{"target":"ns1.example.com"}},
                    {"name":"ns1","type":"A","ttl":3600,"data":{"address":"203.0.113.53"}},
                    {"name":"ns1","type":"AAAA","ttl":3600,"data":{"address":"2001:db8::53"}}
                ]
            }"#,
        );

        let resolver = ZoneAuthorityResolver::from_source("example.com", &zone_file, None, None)
            .expect("zone resolver should load from file");
        let query = make_query("example.com.", RecordType::NS);

        let response_bytes = resolver
            .resolve(query)
            .await
            .expect("resolver should answer NS query");
        let response = Message::from_vec(&response_bytes).expect("response should parse");

        assert!(response
            .answers
            .iter()
            .any(|record| record.record_type() == RecordType::NS));
        assert!(response
            .additionals
            .iter()
            .any(|record| record.record_type() == RecordType::A));
        assert!(response
            .additionals
            .iter()
            .any(|record| record.record_type() == RecordType::AAAA));

        let _ = fs::remove_file(zone_file);
    }

    #[tokio::test]
    async fn missing_apex_ns_is_auto_generated() {
        let zone_file = create_temp_zone_json(
            r#"{
                "zone":"example.org",
                "ttl_default":3600,
                "records":[
                    {"name":"www","type":"A","ttl":300,"data":{"address":"203.0.113.10"}}
                ]
            }"#,
        );

        let resolver = ZoneAuthorityResolver::from_source("example.org", &zone_file, None, None)
            .expect("zone resolver should load from file");
        let query = make_query("example.org.", RecordType::NS);

        let response_bytes = resolver
            .resolve(query)
            .await
            .expect("resolver should answer NS query");
        let response = Message::from_vec(&response_bytes).expect("response should parse");

        let ns_records: Vec<&Record> = response
            .answers
            .iter()
            .filter(|record| record.record_type() == RecordType::NS)
            .collect();
        assert!(
            !ns_records.is_empty(),
            "default NS record should be generated"
        );

        let _ = fs::remove_file(zone_file);
    }

    #[tokio::test]
    async fn missing_apex_soa_is_auto_generated() {
        let zone_file = create_temp_zone_json(
            r#"{
                "zone":"example.net",
                "ttl_default":3600,
                "serial":"2026051201",
                "records":[
                    {"name":"@","type":"NS","ttl":3600,"data":{"target":"ns1.example.net"}}
                ]
            }"#,
        );

        let resolver = ZoneAuthorityResolver::from_source("example.net", &zone_file, None, None)
            .expect("zone resolver should load from file");
        let query = make_query("missing.example.net.", RecordType::A);

        let response_bytes = resolver
            .resolve(query)
            .await
            .expect("resolver should answer missing-name query");
        let response = Message::from_vec(&response_bytes).expect("response should parse");

        assert_eq!(response.response_code, ResponseCode::NXDomain);
        assert!(response
            .authorities
            .iter()
            .any(|record| record.record_type() == RecordType::SOA));

        let _ = fs::remove_file(zone_file);
    }

    #[tokio::test]
    async fn supports_caa_tlsa_and_naptr_records() {
        let zone_file = create_temp_zone_json(
            r#"{
                "zone":"example.io",
                "ttl_default":3600,
                "records":[
                    {"name":"@","type":"CAA","ttl":3600,"data":{"flags":0,"tag":"issue","value":"letsencrypt.org"}},
                    {"name":"_443._tcp","type":"TLSA","ttl":3600,"data":{"usage":3,"selector":1,"matching_type":1,"certificate":"a1b2c3d4"}},
                    {"name":"_sip._udp","type":"NAPTR","ttl":3600,"data":{"order":100,"preference":10,"flags":"S","service":"SIP+D2U","regexp":"","replacement":"_sip._udp.example.io"}}
                ]
            }"#,
        );

        let resolver = ZoneAuthorityResolver::from_source("example.io", &zone_file, None, None)
            .expect("zone resolver should load from file");

        let caa_query = make_query("example.io.", RecordType::CAA);
        let caa_response = resolver
            .resolve(caa_query)
            .await
            .expect("resolver should answer CAA query");
        let caa_message = Message::from_vec(&caa_response).expect("CAA response should parse");
        assert!(caa_message
            .answers
            .iter()
            .any(|record| record.record_type() == RecordType::CAA));

        let tlsa_query = make_query("_443._tcp.example.io.", RecordType::TLSA);
        let tlsa_response = resolver
            .resolve(tlsa_query)
            .await
            .expect("resolver should answer TLSA query");
        let tlsa_message = Message::from_vec(&tlsa_response).expect("TLSA response should parse");
        assert!(tlsa_message
            .answers
            .iter()
            .any(|record| record.record_type() == RecordType::TLSA));

        let naptr_query = make_query("_sip._udp.example.io.", RecordType::NAPTR);
        let naptr_response = resolver
            .resolve(naptr_query)
            .await
            .expect("resolver should answer NAPTR query");
        let naptr_message =
            Message::from_vec(&naptr_response).expect("NAPTR response should parse");
        assert!(naptr_message
            .answers
            .iter()
            .any(|record| record.record_type() == RecordType::NAPTR));

        let _ = fs::remove_file(zone_file);
    }
}
