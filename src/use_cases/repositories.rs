//! Repository trait definitions for database-backed operational config.
//!
//! These traits define the data-access contracts consumed by use-case
//! orchestration.  Implementations live in `frameworks::database`.

use anyhow::Result;
use async_trait::async_trait;

use crate::use_cases::repository_types::{
    FilterCacheDocumentRecord, FilterListRecord, FilteringConfigRecord, ResolverConfigRecord,
    UpstreamServerRecord, ZoneDiscoveryRecord, ZoneRecord, ZoneServerRecord,
};

// ---------------------------------------------------------------------------
// Filter lists (blocklists / allowlists)
// ---------------------------------------------------------------------------

#[async_trait]
pub trait FilterListRepository: Send + Sync {
    async fn get_all(&self) -> Result<Vec<FilterListRecord>>;
    async fn get_by_name(&self, name: &str) -> Result<Option<FilterListRecord>>;
    async fn create(&self, record: &FilterListRecord) -> Result<()>;
    async fn update(&self, record: &FilterListRecord) -> Result<()>;
    async fn delete(&self, id: &str) -> Result<()>;
    async fn set_enabled(&self, id: &str, enabled: bool) -> Result<()>;
    async fn count(&self) -> Result<i64>;
}

// ---------------------------------------------------------------------------
// Filter cache documents
// ---------------------------------------------------------------------------

#[async_trait]
pub trait FilterCacheRepository: Send + Sync {
    async fn load(&self, key: &str) -> Result<Option<FilterCacheDocumentRecord>>;
    async fn store(&self, record: &FilterCacheDocumentRecord) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Filtering config (singleton)
// ---------------------------------------------------------------------------

#[async_trait]
pub trait FilteringConfigRepository: Send + Sync {
    async fn get(&self) -> Result<FilteringConfigRecord>;
    async fn update(&self, record: &FilteringConfigRecord) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Upstream resolver config
// ---------------------------------------------------------------------------

#[async_trait]
pub trait UpstreamConfigRepository: Send + Sync {
    async fn get_resolver_config(&self) -> Result<ResolverConfigRecord>;
    async fn update_resolver_config(&self, record: &ResolverConfigRecord) -> Result<()>;
    async fn get_all_servers(&self) -> Result<Vec<UpstreamServerRecord>>;
    async fn create_server(&self, record: &UpstreamServerRecord) -> Result<()>;
    async fn delete_all_servers(&self) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Zones
// ---------------------------------------------------------------------------

#[async_trait]
pub trait ZoneRepository: Send + Sync {
    async fn get_all_with_servers(&self) -> Result<Vec<ZoneRecord>>;
    async fn get_by_zone(&self, zone: &str) -> Result<Option<ZoneRecord>>;
    async fn create_zone(&self, record: &ZoneRecord) -> Result<()>;
    async fn update_zone(&self, record: &ZoneRecord) -> Result<()>;
    async fn create_zone_server(&self, record: &ZoneServerRecord) -> Result<()>;
    async fn delete_zone(&self, id: &str) -> Result<()>;
    async fn delete_zone_servers(&self, zone_id: &str) -> Result<()>;
    async fn delete_all_zones(&self) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Zone discovery
// ---------------------------------------------------------------------------

#[async_trait]
pub trait ZoneDiscoveryRepository: Send + Sync {
    async fn get_all(&self) -> Result<Vec<ZoneDiscoveryRecord>>;
    async fn get_by_id(&self, id: &str) -> Result<Option<ZoneDiscoveryRecord>>;
    async fn create(&self, record: &ZoneDiscoveryRecord) -> Result<()>;
    async fn update(&self, record: &ZoneDiscoveryRecord) -> Result<()>;
    async fn delete(&self, id: &str) -> Result<()>;
    async fn delete_all(&self) -> Result<()>;
}
