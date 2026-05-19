use anyhow::{Context, Result};

#[cfg(all(
    feature = "db-sqlite",
    not(feature = "db-mysql"),
    not(feature = "db-postgres")
))]
pub type DbPool = sqlx::SqlitePool;

#[cfg(feature = "db-mysql")]
pub type DbPool = sqlx::MySqlPool;

#[cfg(all(feature = "db-postgres", not(feature = "db-mysql")))]
pub type DbPool = sqlx::PgPool;

/// Initialises a database connection pool and runs pending migrations.
///
/// `url` is the database connection string (e.g.
/// `sqlite:///var/lib/dns-filter/dns-filter.db`).
///
/// Migration SQL is embedded in the binary at compile time via `sqlx::migrate!()`.
pub async fn init_pool(url: &str) -> Result<DbPool> {
    #[cfg(all(
        feature = "db-sqlite",
        not(feature = "db-mysql"),
        not(feature = "db-postgres")
    ))]
    let pool = {
        use std::path::Path;
        use std::str::FromStr;
        // For SQLite, ensure parent directory exists so the file can be created.
        if let Some(path) = url.strip_prefix("sqlite://") {
            if let Some(parent) = Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).with_context(|| {
                        format!("failed to create database directory '{}'", parent.display())
                    })?;
                }
            }
        }

        // Append create mode if not already specified so SQLite creates the file.
        let connect_url = if url.contains("mode=") {
            url.to_string()
        } else if url.contains('?') {
            format!("{url}&mode=rwc")
        } else {
            format!("{url}?mode=rwc")
        };

        let opts = sqlx::sqlite::SqliteConnectOptions::from_str(&connect_url)
            .with_context(|| format!("failed to parse database URL: {url}"))?
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .busy_timeout(std::time::Duration::from_secs(5));

        sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await
            .with_context(|| format!("failed to connect to database at {url}"))?
    };

    #[cfg(feature = "db-mysql")]
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(5)
        .connect(url)
        .await
        .with_context(|| format!("failed to connect to database at {url}"))?;

    #[cfg(all(feature = "db-postgres", not(feature = "db-mysql")))]
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(url)
        .await
        .with_context(|| format!("failed to connect to database at {url}"))?;

    run_migrations(&pool).await?;

    Ok(pool)
}

/// Runs pending migrations embedded in the binary.
async fn run_migrations(pool: &DbPool) -> Result<()> {
    #[cfg(all(
        feature = "db-sqlite",
        not(feature = "db-mysql"),
        not(feature = "db-postgres")
    ))]
    let migrator = sqlx::migrate!("migrations/sqlite");

    #[cfg(feature = "db-mysql")]
    let migrator = sqlx::migrate!("migrations/mysql");

    #[cfg(all(feature = "db-postgres", not(feature = "db-mysql")))]
    let migrator = sqlx::migrate!("migrations/postgres");

    migrator
        .run(pool)
        .await
        .context("failed to run database migrations")?;

    tracing::info!("database migrations applied (embedded)");

    Ok(())
}
