use anyhow::{Context, Result};
use sqlx::migrate::Migrator;
use std::path::Path;

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

/// Returns the migration directory name for the compiled database backend.
fn migration_dir() -> &'static str {
    #[cfg(feature = "db-mysql")]
    {
        "mysql"
    }
    #[cfg(all(feature = "db-postgres", not(feature = "db-mysql")))]
    {
        "postgres"
    }
    #[cfg(all(
        feature = "db-sqlite",
        not(feature = "db-mysql"),
        not(feature = "db-postgres")
    ))]
    {
        "sqlite"
    }
}

/// Initialises a database connection pool and runs pending migrations.
///
/// `url` is the database connection string (e.g.
/// `sqlite:///var/lib/dns-filter/dns-filter.db`).
///
/// Migration files are loaded from `./migrations/<backend>/` relative to the
/// current working directory.  In release builds the migrations directory is
/// looked up next to the binary as a fallback.
pub async fn init_pool(url: &str) -> Result<DbPool> {
    #[cfg(all(
        feature = "db-sqlite",
        not(feature = "db-mysql"),
        not(feature = "db-postgres")
    ))]
    let pool = {
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

        sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&connect_url)
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

/// Runs pending migrations from the backend-specific migrations directory.
async fn run_migrations(pool: &DbPool) -> Result<()> {
    let dir = migration_dir();

    // Try <cwd>/migrations/<backend> first, then next to the executable.
    let cwd_path = format!("migrations/{dir}");
    let migrations_path = if Path::new(&cwd_path).is_dir() {
        cwd_path
    } else {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_default();
        let alt = exe_dir.join("migrations").join(dir);
        alt.to_string_lossy().into_owned()
    };

    let migrator = Migrator::new(Path::new(&migrations_path))
        .await
        .with_context(|| format!("failed to load migrations from '{migrations_path}'"))?;

    migrator
        .run(pool)
        .await
        .context("failed to run database migrations")?;

    tracing::info!(path = %migrations_path, "database migrations applied");

    Ok(())
}
