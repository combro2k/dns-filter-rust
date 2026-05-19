use anyhow::{Context, Result};
use async_trait::async_trait;

use crate::frameworks::database::pool::DbPool;
use crate::use_cases::repositories::{ZoneDiscoveryRepository, ZoneRepository};
use crate::use_cases::repository_types::{ZoneDiscoveryRecord, ZoneRecord, ZoneServerRecord};

// ---------------------------------------------------------------------------
// Zone repository
// ---------------------------------------------------------------------------

pub struct SqlxZoneRepository {
    pool: DbPool,
}

impl SqlxZoneRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneRepository for SqlxZoneRepository {
    async fn get_all_with_servers(&self) -> Result<Vec<ZoneRecord>> {
        let zone_rows = sqlx::query_as::<_, ZoneRow>(
            "SELECT id, zone, enabled, bypass_filter, fallback_to_default_resolvers, strategy \
             FROM zones ORDER BY zone",
        )
        .fetch_all(&self.pool)
        .await
        .context("failed to fetch zones")?;

        let server_rows = sqlx::query_as::<_, ZoneServerRow>(
            "SELECT id, zone_id, enabled, protocol, address, auth_token, auth_username, auth_password, \
             check_interval, max_hops, nameserver_ip_family, root_hints_path, root_key_path, dnssec, sort_order \
             FROM zone_servers ORDER BY sort_order, id",
        )
        .fetch_all(&self.pool)
        .await
        .context("failed to fetch zone servers")?;

        let mut zones: Vec<ZoneRecord> = zone_rows
            .into_iter()
            .map(|row| ZoneRecord {
                id: row.id,
                zone: row.zone,
                enabled: row.enabled,
                bypass_filter: row.bypass_filter,
                fallback_to_default_resolvers: row.fallback_to_default_resolvers,
                strategy: row.strategy,
                servers: Vec::new(),
            })
            .collect();

        for server_row in server_rows {
            if let Some(zone) = zones.iter_mut().find(|z| z.id == server_row.zone_id) {
                zone.servers.push(ZoneServerRecord::from(server_row));
            }
        }

        Ok(zones)
    }

    async fn create_zone(&self, record: &ZoneRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO zones (id, zone, enabled, bypass_filter, fallback_to_default_resolvers, strategy) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&record.id)
        .bind(&record.zone)
        .bind(record.enabled)
        .bind(record.bypass_filter)
        .bind(record.fallback_to_default_resolvers)
        .bind(&record.strategy)
        .execute(&self.pool)
        .await
        .with_context(|| format!("failed to insert zone '{}'", record.zone))?;

        Ok(())
    }

    async fn create_zone_server(&self, record: &ZoneServerRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO zone_servers \
             (id, zone_id, enabled, protocol, address, auth_token, auth_username, auth_password, \
              check_interval, max_hops, nameserver_ip_family, root_hints_path, root_key_path, dnssec, sort_order) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&record.id)
        .bind(&record.zone_id)
        .bind(record.enabled)
        .bind(&record.protocol)
        .bind(&record.address)
        .bind(&record.auth_token)
        .bind(&record.auth_username)
        .bind(&record.auth_password)
        .bind(&record.check_interval)
        .bind(record.max_hops)
        .bind(&record.nameserver_ip_family)
        .bind(&record.root_hints_path)
        .bind(&record.root_key_path)
        .bind(record.dnssec)
        .bind(record.sort_order)
        .execute(&self.pool)
        .await
        .with_context(|| format!("failed to insert zone server '{}'", record.id))?;

        Ok(())
    }

    async fn delete_all_zones(&self) -> Result<()> {
        // zone_servers cascade-deletes via FK
        sqlx::query("DELETE FROM zones")
            .execute(&self.pool)
            .await
            .context("failed to delete all zones")?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Zone discovery repository
// ---------------------------------------------------------------------------

pub struct SqlxZoneDiscoveryRepository {
    pool: DbPool,
}

impl SqlxZoneDiscoveryRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneDiscoveryRepository for SqlxZoneDiscoveryRepository {
    async fn get_all(&self) -> Result<Vec<ZoneDiscoveryRecord>> {
        let rows = sqlx::query_as::<_, ZoneDiscoveryRow>(
            "SELECT id, enabled, address, check_interval, allowed_types, bypass_filter, \
             fallback_to_default_resolvers, auth_token, auth_username, auth_password \
             FROM zone_discovery ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await
        .context("failed to fetch zone discovery entries")?;

        Ok(rows.into_iter().map(ZoneDiscoveryRecord::from).collect())
    }

    async fn create(&self, record: &ZoneDiscoveryRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO zone_discovery \
             (id, enabled, address, check_interval, allowed_types, bypass_filter, \
              fallback_to_default_resolvers, auth_token, auth_username, auth_password) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&record.id)
        .bind(record.enabled)
        .bind(&record.address)
        .bind(&record.check_interval)
        .bind(&record.allowed_types)
        .bind(record.bypass_filter)
        .bind(record.fallback_to_default_resolvers)
        .bind(&record.auth_token)
        .bind(&record.auth_username)
        .bind(&record.auth_password)
        .execute(&self.pool)
        .await
        .with_context(|| format!("failed to insert zone discovery '{}'", record.id))?;

        Ok(())
    }

    async fn delete_all(&self) -> Result<()> {
        sqlx::query("DELETE FROM zone_discovery")
            .execute(&self.pool)
            .await
            .context("failed to delete all zone discovery entries")?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal row types
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct ZoneRow {
    id: String,
    zone: String,
    enabled: bool,
    bypass_filter: bool,
    fallback_to_default_resolvers: bool,
    strategy: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ZoneServerRow {
    id: String,
    zone_id: String,
    enabled: bool,
    protocol: String,
    address: String,
    auth_token: Option<String>,
    auth_username: Option<String>,
    auth_password: Option<String>,
    check_interval: Option<String>,
    max_hops: Option<i32>,
    nameserver_ip_family: Option<String>,
    root_hints_path: Option<String>,
    root_key_path: Option<String>,
    dnssec: bool,
    sort_order: i32,
}

impl From<ZoneServerRow> for ZoneServerRecord {
    fn from(row: ZoneServerRow) -> Self {
        Self {
            id: row.id,
            zone_id: row.zone_id,
            enabled: row.enabled,
            protocol: row.protocol,
            address: row.address,
            auth_token: row.auth_token,
            auth_username: row.auth_username,
            auth_password: row.auth_password,
            check_interval: row.check_interval,
            max_hops: row.max_hops,
            nameserver_ip_family: row.nameserver_ip_family,
            root_hints_path: row.root_hints_path,
            root_key_path: row.root_key_path,
            dnssec: row.dnssec,
            sort_order: row.sort_order,
        }
    }
}

#[derive(sqlx::FromRow)]
struct ZoneDiscoveryRow {
    id: String,
    enabled: bool,
    address: String,
    check_interval: Option<String>,
    allowed_types: String,
    bypass_filter: bool,
    fallback_to_default_resolvers: bool,
    auth_token: Option<String>,
    auth_username: Option<String>,
    auth_password: Option<String>,
}

impl From<ZoneDiscoveryRow> for ZoneDiscoveryRecord {
    fn from(row: ZoneDiscoveryRow) -> Self {
        Self {
            id: row.id,
            enabled: row.enabled,
            address: row.address,
            check_interval: row.check_interval,
            allowed_types: row.allowed_types,
            bypass_filter: row.bypass_filter,
            fallback_to_default_resolvers: row.fallback_to_default_resolvers,
            auth_token: row.auth_token,
            auth_username: row.auth_username,
            auth_password: row.auth_password,
        }
    }
}
