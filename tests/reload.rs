#[cfg(test)]
mod reload_tests {
    use dns_filter::use_cases::reload::reload_config;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    fn create_temp_config(content: &str) -> PathBuf {
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join(format!("dns-filter-test-{}.yaml", std::process::id()));
        let mut file = fs::File::create(&path).expect("failed to create temp file");
        file.write_all(content.as_bytes())
            .expect("failed to write to temp file");
        path
    }

    #[test]
    fn reload_config_fails_on_nonexistent_file() {
        let result = reload_config("/this/path/does/not/exist.yaml");
        assert!(result.is_err());
    }

    #[test]
    fn reload_config_fails_on_invalid_yaml() {
        let path = create_temp_config("{{ invalid: yaml: syntax");
        let result = reload_config(path.to_str().unwrap());
        assert!(result.is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn reload_config_fails_on_missing_upstreams() {
        let content = r#"
listen:
  dns:
    enabled: true
    address: "127.0.0.1"
    port: 53
upstreams:
  strategy: round_robin
  servers: []
blocklists: []
allowlists: []
"#;
        let path = create_temp_config(content);
        let result = reload_config(path.to_str().unwrap());
        assert!(
            result.is_err(),
            "should fail with no enabled upstream servers"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn reload_config_succeeds_with_valid_config() {
        let content = r#"
listen:
  dns:
    enabled: true
    address: "127.0.0.1"
    port: 53
upstreams:
  strategy: round_robin
  servers:
    - protocol: dns
      address: "1.1.1.1:53"
      enabled: true
blocklists: []
allowlists: []
logging:
  enabled: false
"#;
        let path = create_temp_config(content);
        let result = reload_config(path.to_str().unwrap());
        if let Err(e) = &result {
            eprintln!("Reload failed: {:#}", e);
        }
        assert!(result.is_ok(), "should succeed with valid config");

        let (resolver, filter, _policy) = result.expect("unwrap result");
        // Verify we got valid instances by checking they are not null
        let resolver_ptr = &*resolver as *const _ as *const ();
        let filter_ptr = &*filter as *const _ as *const ();
        assert!(!resolver_ptr.is_null());
        assert!(!filter_ptr.is_null());
        let _ = fs::remove_file(path);
    }
}
