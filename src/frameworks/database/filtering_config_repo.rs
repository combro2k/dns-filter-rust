use anyhow::{Context, Result};
use async_trait::async_trait;

use crate::frameworks::database::pool::DbPool;
use crate::use_cases::repositories::FilteringConfigRepository;
use crate::use_cases::repository_types::FilteringConfigRecord;

pub struct SqlxFilteringConfigRepository {
    pool: DbPool,
}

impl SqlxFilteringConfigRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl FilteringConfigRepository for SqlxFilteringConfigRepository {
    async fn get(&self) -> Result<FilteringConfigRecord> {
        let row = sqlx::query_as::<_, FilteringConfigRow>(
            "SELECT sinkhole_ipv4, sinkhole_ipv6, any_query_policy FROM filtering_config WHERE id = 1",
        )
        .fetch_one(&self.pool)
        .await
        .context("failed to fetch filtering config")?;

        Ok(FilteringConfigRecord {
            sinkhole_ipv4: row.sinkhole_ipv4,
            sinkhole_ipv6: row.sinkhole_ipv6,
            any_query_policy: row.any_query_policy,
        })
    }

    async fn update(&self, record: &FilteringConfigRecord) -> Result<()> {
        sqlx::query(
            "UPDATE filtering_config SET sinkhole_ipv4 = ?, sinkhole_ipv6 = ?, any_query_policy = ? WHERE id = 1",
        )
        .bind(&record.sinkhole_ipv4)
        .bind(&record.sinkhole_ipv6)
        .bind(&record.any_query_policy)
        .execute(&self.pool)
        .await
        .context("failed to update filtering config")?;

        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct FilteringConfigRow {
    sinkhole_ipv4: String,
    sinkhole_ipv6: String,
    any_query_policy: String,
}
