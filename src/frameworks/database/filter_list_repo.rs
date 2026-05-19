use anyhow::{Context, Result};
use async_trait::async_trait;

use crate::frameworks::database::pool::DbPool;
use crate::use_cases::repositories::FilterListRepository;
use crate::use_cases::repository_types::FilterListRecord;

pub struct SqlxFilterListRepository {
    pool: DbPool,
}

impl SqlxFilterListRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl FilterListRepository for SqlxFilterListRepository {
    async fn get_all(&self) -> Result<Vec<FilterListRecord>> {
        let rows = sqlx::query_as::<_, FilterListRow>(
            "SELECT id, name, kind, url, interval_seconds, enabled, list_type FROM filter_lists ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
        .context("failed to fetch filter lists")?;

        Ok(rows.into_iter().map(FilterListRecord::from).collect())
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<FilterListRecord>> {
        let row = sqlx::query_as::<_, FilterListRow>(
            "SELECT id, name, kind, url, interval_seconds, enabled, list_type FROM filter_lists WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .context("failed to fetch filter list by name")?;

        Ok(row.map(FilterListRecord::from))
    }

    async fn create(&self, record: &FilterListRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO filter_lists (id, name, kind, url, interval_seconds, enabled, list_type) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&record.id)
        .bind(&record.name)
        .bind(&record.kind)
        .bind(&record.url)
        .bind(record.interval_seconds)
        .bind(record.enabled)
        .bind(&record.list_type)
        .execute(&self.pool)
        .await
        .with_context(|| format!("failed to insert filter list '{}'", record.name))?;

        Ok(())
    }

    async fn update(&self, record: &FilterListRecord) -> Result<()> {
        sqlx::query(
            "UPDATE filter_lists SET name = ?, kind = ?, url = ?, interval_seconds = ?, enabled = ?, list_type = ? WHERE id = ?",
        )
        .bind(&record.name)
        .bind(&record.kind)
        .bind(&record.url)
        .bind(record.interval_seconds)
        .bind(record.enabled)
        .bind(&record.list_type)
        .bind(&record.id)
        .execute(&self.pool)
        .await
        .with_context(|| format!("failed to update filter list '{}'", record.name))?;

        Ok(())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM filter_lists WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .with_context(|| format!("failed to delete filter list '{id}'"))?;

        Ok(())
    }

    async fn set_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        sqlx::query("UPDATE filter_lists SET enabled = ? WHERE id = ?")
            .bind(enabled)
            .bind(id)
            .execute(&self.pool)
            .await
            .with_context(|| format!("failed to set enabled={enabled} for filter list '{id}'"))?;

        Ok(())
    }

    async fn count(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM filter_lists")
            .fetch_one(&self.pool)
            .await
            .context("failed to count filter lists")?;

        Ok(row.0)
    }
}

// Internal row type for sqlx decoding.
#[derive(sqlx::FromRow)]
struct FilterListRow {
    id: String,
    name: String,
    kind: String,
    url: String,
    interval_seconds: i64,
    enabled: bool,
    list_type: String,
}

impl From<FilterListRow> for FilterListRecord {
    fn from(row: FilterListRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            kind: row.kind,
            url: row.url,
            interval_seconds: row.interval_seconds,
            enabled: row.enabled,
            list_type: row.list_type,
        }
    }
}
