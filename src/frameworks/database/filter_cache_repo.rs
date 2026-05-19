use anyhow::{Context, Result};
use async_trait::async_trait;

use crate::frameworks::database::pool::DbPool;
use crate::use_cases::repositories::FilterCacheRepository;
use crate::use_cases::repository_types::FilterCacheDocumentRecord;

pub struct SqlxFilterCacheRepository {
    pool: DbPool,
}

impl SqlxFilterCacheRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl FilterCacheRepository for SqlxFilterCacheRepository {
    async fn load(&self, key: &str) -> Result<Option<FilterCacheDocumentRecord>> {
        let row = sqlx::query_as::<_, FilterCacheRow>(
            "SELECT key, value FROM filter_cache_documents WHERE key = ?",
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .context("failed to load filter cache document")?;

        Ok(row.map(|r| FilterCacheDocumentRecord {
            key: r.key,
            value: r.value,
        }))
    }

    async fn store(&self, record: &FilterCacheDocumentRecord) -> Result<()> {
        #[cfg(all(
            feature = "db-sqlite",
            not(feature = "db-mysql"),
            not(feature = "db-postgres")
        ))]
        {
            sqlx::query(
                "INSERT INTO filter_cache_documents (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            )
            .bind(&record.key)
            .bind(&record.value)
            .execute(&self.pool)
            .await
            .with_context(|| format!("failed to upsert filter cache document '{}'", record.key))?;
        }

        #[cfg(feature = "db-mysql")]
        {
            sqlx::query(
                "INSERT INTO filter_cache_documents (`key`, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value)",
            )
            .bind(&record.key)
            .bind(&record.value)
            .execute(&self.pool)
            .await
            .with_context(|| format!("failed to upsert filter cache document '{}'", record.key))?;
        }

        #[cfg(all(feature = "db-postgres", not(feature = "db-mysql")))]
        {
            sqlx::query(
                "INSERT INTO filter_cache_documents (key, value) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value",
            )
            .bind(&record.key)
            .bind(&record.value)
            .execute(&self.pool)
            .await
            .with_context(|| format!("failed to upsert filter cache document '{}'", record.key))?;
        }

        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct FilterCacheRow {
    key: String,
    value: String,
}
