#[cfg(all(
    test,
    feature = "db-sqlite",
    not(feature = "db-mysql"),
    not(feature = "db-postgres")
))]
mod tests {
    use crate::frameworks::database::{
        SqlxFilterCacheRepository, SqlxFilterListRepository, SqlxFilteringConfigRepository,
        SqlxUpstreamConfigRepository, SqlxZoneDiscoveryRepository, SqlxZoneRepository,
    };
    use crate::use_cases::repositories::{
        FilterCacheRepository, FilterListRepository, FilteringConfigRepository,
        UpstreamConfigRepository, ZoneDiscoveryRepository, ZoneRepository,
    };
    use crate::use_cases::repository_types::{
        FilterCacheDocumentRecord, FilterListRecord, FilteringConfigRecord, ResolverConfigRecord,
        UpstreamServerRecord, ZoneDiscoveryRecord, ZoneRecord, ZoneServerRecord,
    };
    use sqlx::SqlitePool;

    async fn setup_test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("connect to in-memory SQLite");

        // Run the migration SQL manually for tests
        let migration_001 = include_str!("../../../migrations/sqlite/001_initial_schema.sql");
        for statement in migration_001.split(';') {
            let trimmed = statement.trim();
            if !trimmed.is_empty() {
                sqlx::query(trimmed)
                    .execute(&pool)
                    .await
                    .unwrap_or_else(|e| panic!("migration statement failed: {e}\nSQL: {trimmed}"));
            }
        }

        let migration_002 =
            include_str!("../../../migrations/sqlite/002_normalize_list_columns.sql");
        for statement in migration_002.split(';') {
            let trimmed = statement.trim();
            if !trimmed.is_empty() {
                sqlx::query(trimmed)
                    .execute(&pool)
                    .await
                    .unwrap_or_else(|e| panic!("migration statement failed: {e}\nSQL: {trimmed}"));
            }
        }

        pool
    }

    // --- FilterListRepository tests ---

    #[tokio::test]
    async fn filter_list_crud() {
        let pool = setup_test_pool().await;
        let repo = SqlxFilterListRepository::new(pool);

        // Initially empty
        assert_eq!(repo.count().await.unwrap(), 0);
        assert!(repo.get_all().await.unwrap().is_empty());

        // Create
        let record = FilterListRecord {
            id: "id-1".to_string(),
            name: "test_list".to_string(),
            kind: "block".to_string(),
            url: "https://example.com/list.txt".to_string(),
            interval_seconds: 3600,
            enabled: true,
            list_type: "adguard".to_string(),
        };
        repo.create(&record).await.unwrap();
        assert_eq!(repo.count().await.unwrap(), 1);

        // Get by name
        let fetched = repo.get_by_name("test_list").await.unwrap().unwrap();
        assert_eq!(fetched.id, "id-1");
        assert_eq!(fetched.kind, "block");
        assert_eq!(fetched.url, "https://example.com/list.txt");

        // Update
        let updated = FilterListRecord {
            url: "https://example.com/updated.txt".to_string(),
            ..record.clone()
        };
        repo.update(&updated).await.unwrap();
        let fetched = repo.get_by_name("test_list").await.unwrap().unwrap();
        assert_eq!(fetched.url, "https://example.com/updated.txt");

        // Set enabled
        repo.set_enabled("id-1", false).await.unwrap();
        let fetched = repo.get_by_name("test_list").await.unwrap().unwrap();
        assert!(!fetched.enabled);

        // Delete
        repo.delete("id-1").await.unwrap();
        assert_eq!(repo.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn filter_list_get_by_name_not_found() {
        let pool = setup_test_pool().await;
        let repo = SqlxFilterListRepository::new(pool);
        assert!(repo.get_by_name("nonexistent").await.unwrap().is_none());
    }

    // --- FilterCacheRepository tests ---

    #[tokio::test]
    async fn filter_cache_store_and_load() {
        let pool = setup_test_pool().await;
        let repo = SqlxFilterCacheRepository::new(pool);

        // Initially empty
        assert!(repo.load("block:test").await.unwrap().is_none());

        // Store
        repo.store(&FilterCacheDocumentRecord {
            key: "block:test".to_string(),
            value: r#"{"kind":"block","domains":["a.com"],"exceptions":[]}"#.to_string(),
        })
        .await
        .unwrap();

        // Load
        let doc = repo.load("block:test").await.unwrap().unwrap();
        assert_eq!(doc.key, "block:test");
        assert!(doc.value.contains("a.com"));

        // Upsert (update)
        repo.store(&FilterCacheDocumentRecord {
            key: "block:test".to_string(),
            value: r#"{"kind":"block","domains":["b.com"],"exceptions":[]}"#.to_string(),
        })
        .await
        .unwrap();

        let doc = repo.load("block:test").await.unwrap().unwrap();
        assert!(doc.value.contains("b.com"));
        assert!(!doc.value.contains("a.com"));
    }

    // --- FilteringConfigRepository tests ---

    #[tokio::test]
    async fn filtering_config_get_and_update() {
        let pool = setup_test_pool().await;
        let repo = SqlxFilteringConfigRepository::new(pool);

        // Default singleton exists from migration
        let config = repo.get().await.unwrap();
        assert_eq!(config.sinkhole_ipv4, "0.0.0.0");
        assert_eq!(config.sinkhole_ipv6, "::");
        assert_eq!(config.any_query_policy, "notimp");

        // Update
        repo.update(&FilteringConfigRecord {
            sinkhole_ipv4: "127.0.0.1".to_string(),
            sinkhole_ipv6: "::1".to_string(),
            any_query_policy: "refused".to_string(),
        })
        .await
        .unwrap();

        let config = repo.get().await.unwrap();
        assert_eq!(config.sinkhole_ipv4, "127.0.0.1");
        assert_eq!(config.any_query_policy, "refused");
    }

    // --- UpstreamConfigRepository tests ---

    #[tokio::test]
    async fn upstream_config_crud() {
        let pool = setup_test_pool().await;
        let repo = SqlxUpstreamConfigRepository::new(pool);

        // Default resolver config
        let config = repo.get_resolver_config().await.unwrap();
        assert_eq!(config.strategy, "round_robin");

        // Update resolver config
        repo.update_resolver_config(&ResolverConfigRecord {
            strategy: "failover".to_string(),
            bootstrap_resolvers: vec!["8.8.8.8".to_string()],
        })
        .await
        .unwrap();
        let config = repo.get_resolver_config().await.unwrap();
        assert_eq!(config.strategy, "failover");

        // Create server
        repo.create_server(&UpstreamServerRecord {
            id: "srv-1".to_string(),
            enabled: true,
            protocol: "dns".to_string(),
            address: "1.1.1.1:53".to_string(),
            auth_token: None,
            auth_username: None,
            auth_password: None,
            max_hops: None,
            nameserver_ip_family: None,
            root_hints_path: None,
            root_key_path: None,
            dnssec: true,
            sort_order: 0,
        })
        .await
        .unwrap();

        let servers = repo.get_all_servers().await.unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].address, "1.1.1.1:53");

        // Delete all
        repo.delete_all_servers().await.unwrap();
        assert!(repo.get_all_servers().await.unwrap().is_empty());
    }

    // --- ZoneRepository tests ---

    #[tokio::test]
    async fn zone_crud_with_servers() {
        let pool = setup_test_pool().await;
        let repo = SqlxZoneRepository::new(pool);

        // Create zone
        repo.create_zone(&ZoneRecord {
            id: "zone-1".to_string(),
            zone: "home.arpa".to_string(),
            enabled: true,
            bypass_filter: true,
            fallback_to_default_resolvers: false,
            strategy: Some("failover".to_string()),
            servers: Vec::new(),
        })
        .await
        .unwrap();

        // Create zone server
        repo.create_zone_server(&ZoneServerRecord {
            id: "zs-1".to_string(),
            zone_id: "zone-1".to_string(),
            enabled: true,
            protocol: "dns".to_string(),
            address: "192.168.1.1:53".to_string(),
            auth_token: None,
            auth_username: None,
            auth_password: None,
            check_interval: None,
            max_hops: None,
            nameserver_ip_family: None,
            root_hints_path: None,
            root_key_path: None,
            dnssec: false,
            sort_order: 0,
        })
        .await
        .unwrap();

        // Get all with servers
        let zones = repo.get_all_with_servers().await.unwrap();
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].zone, "home.arpa");
        assert!(zones[0].bypass_filter);
        assert_eq!(zones[0].servers.len(), 1);
        assert_eq!(zones[0].servers[0].address, "192.168.1.1:53");

        // Delete all (cascade)
        repo.delete_all_zones().await.unwrap();
        assert!(repo.get_all_with_servers().await.unwrap().is_empty());
    }

    // --- ZoneDiscoveryRepository tests ---

    #[tokio::test]
    async fn zone_discovery_crud() {
        let pool = setup_test_pool().await;
        let repo = SqlxZoneDiscoveryRepository::new(pool);

        assert!(repo.get_all().await.unwrap().is_empty());

        repo.create(&ZoneDiscoveryRecord {
            id: "zd-1".to_string(),
            enabled: true,
            address: "https://example.com/zones.json".to_string(),
            check_interval: Some("15m".to_string()),
            allowed_types: vec!["reverse".to_string(), "forward".to_string()],
            bypass_filter: false,
            fallback_to_default_resolvers: true,
            auth_token: Some("secret".to_string()),
            auth_username: None,
            auth_password: None,
        })
        .await
        .unwrap();

        let entries = repo.get_all().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].address, "https://example.com/zones.json");
        assert!(entries[0].fallback_to_default_resolvers);

        repo.delete_all().await.unwrap();
        assert!(repo.get_all().await.unwrap().is_empty());
    }
}
