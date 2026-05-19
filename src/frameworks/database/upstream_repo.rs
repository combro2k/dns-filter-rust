use anyhow::{Context, Result};
use async_trait::async_trait;

use crate::frameworks::database::pool::DbPool;
use crate::use_cases::repositories::UpstreamConfigRepository;
use crate::use_cases::repository_types::{ResolverConfigRecord, UpstreamServerRecord};

pub struct SqlxUpstreamConfigRepository {
    pool: DbPool,
}

impl SqlxUpstreamConfigRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UpstreamConfigRepository for SqlxUpstreamConfigRepository {
    async fn get_resolver_config(&self) -> Result<ResolverConfigRecord> {
        let row = sqlx::query_as::<_, ResolverConfigRow>(
            "SELECT strategy, bootstrap_resolvers FROM resolver_config WHERE id = 1",
        )
        .fetch_one(&self.pool)
        .await
        .context("failed to fetch resolver config")?;

        Ok(ResolverConfigRecord {
            strategy: row.strategy,
            bootstrap_resolvers: row.bootstrap_resolvers,
        })
    }

    async fn update_resolver_config(&self, record: &ResolverConfigRecord) -> Result<()> {
        sqlx::query(
            "UPDATE resolver_config SET strategy = ?, bootstrap_resolvers = ? WHERE id = 1",
        )
        .bind(&record.strategy)
        .bind(&record.bootstrap_resolvers)
        .execute(&self.pool)
        .await
        .context("failed to update resolver config")?;

        Ok(())
    }

    async fn get_all_servers(&self) -> Result<Vec<UpstreamServerRecord>> {
        let rows = sqlx::query_as::<_, UpstreamServerRow>(
            "SELECT id, enabled, protocol, address, auth_token, auth_username, auth_password, \
             max_hops, nameserver_ip_family, root_hints_path, root_key_path, dnssec, sort_order \
             FROM upstream_servers ORDER BY sort_order, id",
        )
        .fetch_all(&self.pool)
        .await
        .context("failed to fetch upstream servers")?;

        Ok(rows.into_iter().map(UpstreamServerRecord::from).collect())
    }

    async fn create_server(&self, record: &UpstreamServerRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO upstream_servers \
             (id, enabled, protocol, address, auth_token, auth_username, auth_password, \
              max_hops, nameserver_ip_family, root_hints_path, root_key_path, dnssec, sort_order) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&record.id)
        .bind(record.enabled)
        .bind(&record.protocol)
        .bind(&record.address)
        .bind(&record.auth_token)
        .bind(&record.auth_username)
        .bind(&record.auth_password)
        .bind(record.max_hops)
        .bind(&record.nameserver_ip_family)
        .bind(&record.root_hints_path)
        .bind(&record.root_key_path)
        .bind(record.dnssec)
        .bind(record.sort_order)
        .execute(&self.pool)
        .await
        .with_context(|| format!("failed to insert upstream server '{}'", record.id))?;

        Ok(())
    }

    async fn delete_all_servers(&self) -> Result<()> {
        sqlx::query("DELETE FROM upstream_servers")
            .execute(&self.pool)
            .await
            .context("failed to delete all upstream servers")?;

        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct ResolverConfigRow {
    strategy: String,
    bootstrap_resolvers: String,
}

#[derive(sqlx::FromRow)]
struct UpstreamServerRow {
    id: String,
    enabled: bool,
    protocol: String,
    address: String,
    auth_token: Option<String>,
    auth_username: Option<String>,
    auth_password: Option<String>,
    max_hops: Option<i32>,
    nameserver_ip_family: Option<String>,
    root_hints_path: Option<String>,
    root_key_path: Option<String>,
    dnssec: bool,
    sort_order: i32,
}

impl From<UpstreamServerRow> for UpstreamServerRecord {
    fn from(row: UpstreamServerRow) -> Self {
        Self {
            id: row.id,
            enabled: row.enabled,
            protocol: row.protocol,
            address: row.address,
            auth_token: row.auth_token,
            auth_username: row.auth_username,
            auth_password: row.auth_password,
            max_hops: row.max_hops,
            nameserver_ip_family: row.nameserver_ip_family,
            root_hints_path: row.root_hints_path,
            root_key_path: row.root_key_path,
            dnssec: row.dnssec,
            sort_order: row.sort_order,
        }
    }
}
