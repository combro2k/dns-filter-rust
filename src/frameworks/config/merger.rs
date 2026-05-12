use anyhow::{Context, Result};
use serde_yaml::Value;

const EXAMPLE_CONFIG: &str = include_str!("../../../package/config/config.example.yaml");

/// Deep-merge two YAML values.  `overlay` wins on conflicts.
///
/// - **Mappings**: recursively merged key-by-key; overlay keys win.
/// - **Sequences**: overlay replaces base entirely.
/// - **Scalars/nulls**: overlay wins.
fn deep_merge(base: Value, overlay: Value) -> Value {
    match (base, overlay) {
        (Value::Mapping(mut base_map), Value::Mapping(overlay_map)) => {
            for (key, overlay_val) in overlay_map {
                let merged = if let Some(base_val) = base_map.remove(&key) {
                    deep_merge(base_val, overlay_val)
                } else {
                    overlay_val
                };
                base_map.insert(key, merged);
            }
            Value::Mapping(base_map)
        }
        // For sequences, scalars, and all other types the overlay wins.
        (_base, overlay) => overlay,
    }
}

/// Merge the embedded example config with a user-provided config string.
///
/// The user config is the overlay — every value present in the user config
/// wins over the example default.  Sections the user omits are filled from
/// the example config.
///
/// Returns the merged YAML as a string.
pub fn merge_with_example(user_config: &str) -> Result<String> {
    let mut base: Value = serde_yaml::from_str(EXAMPLE_CONFIG)
        .context("failed to parse embedded example config (this is a bug)")?;

    let mut overlay: Value =
        serde_yaml::from_str(user_config).context("failed to parse user config file")?;

    // Normalize legacy `address` → `addresses` before merging so the keys
    // align and the overlay (user) value properly wins over the base.
    normalize_listen_addresses(&mut base);
    normalize_listen_addresses(&mut overlay);

    let merged = deep_merge(base, overlay);

    serde_yaml::to_string(&merged).context("failed to serialize merged config")
}

/// Normalize `address` (singular, legacy) to `addresses` (list) in all
/// listener socket sections under `listen:`.
///
/// This ensures the deep-merge sees a single canonical key (`addresses`)
/// rather than treating `address` and `addresses` as separate entries.
///
/// - If both `address` and `addresses` exist, `address` is removed (the
///   canonical `addresses` list wins).
/// - If only `address` exists (string), it is converted to a single-element
///   `addresses` list.
fn normalize_listen_addresses(root: &mut Value) {
    let listen = match root.get_mut("listen").and_then(Value::as_mapping_mut) {
        Some(m) => m,
        None => return,
    };

    let listener_keys: Vec<Value> = listen.keys().cloned().collect();
    for key in listener_keys {
        let section = match listen.get_mut(&key).and_then(Value::as_mapping_mut) {
            Some(m) => m,
            None => continue,
        };

        let addr_key = Value::String("address".into());
        let addrs_key = Value::String("addresses".into());

        let has_addresses = section.contains_key(&addrs_key);
        let has_address = section.contains_key(&addr_key);

        if has_address && has_addresses {
            // Both present: remove the legacy key; `addresses` wins.
            section.remove(&addr_key);
        } else if has_address && !has_addresses {
            // Only legacy key: convert to canonical list form.
            if let Some(addr_val) = section.remove(&addr_key) {
                let list = match addr_val {
                    Value::String(_) => Value::Sequence(vec![addr_val]),
                    Value::Sequence(_) => addr_val,
                    other => Value::Sequence(vec![other]),
                };
                section.insert(addrs_key, list);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_override_user_wins() {
        let base = "listen:\n  dns:\n    port: 53\n";
        let overlay = "listen:\n  dns:\n    port: 5353\n";

        let base_val: Value = serde_yaml::from_str(base).unwrap();
        let overlay_val: Value = serde_yaml::from_str(overlay).unwrap();
        let merged = deep_merge(base_val, overlay_val);

        let port = merged["listen"]["dns"]["port"].as_u64().unwrap();
        assert_eq!(port, 5353);
    }

    #[test]
    fn recursive_map_merge_preserves_both_keys() {
        let base = "listen:\n  dns:\n    port: 53\n    enabled: true\n";
        let overlay = "listen:\n  dns:\n    port: 5353\n";

        let base_val: Value = serde_yaml::from_str(base).unwrap();
        let overlay_val: Value = serde_yaml::from_str(overlay).unwrap();
        let merged = deep_merge(base_val, overlay_val);

        assert_eq!(merged["listen"]["dns"]["port"].as_u64().unwrap(), 5353);
        assert!(merged["listen"]["dns"]["enabled"].as_bool().unwrap());
    }

    #[test]
    fn array_replacement_user_array_wins() {
        let base = "blocklists:\n  - name: a\n    url: http://a\n";
        let overlay = "blocklists:\n  - name: b\n    url: http://b\n";

        let base_val: Value = serde_yaml::from_str(base).unwrap();
        let overlay_val: Value = serde_yaml::from_str(overlay).unwrap();
        let merged = deep_merge(base_val, overlay_val);

        let list = merged["blocklists"].as_sequence().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["name"].as_str().unwrap(), "b");
    }

    #[test]
    fn missing_section_filled_from_base() {
        let base = "listen:\n  dns:\n    port: 53\nlogging:\n  stdout:\n    enabled: true\n";
        let overlay = "listen:\n  dns:\n    port: 5353\n";

        let base_val: Value = serde_yaml::from_str(base).unwrap();
        let overlay_val: Value = serde_yaml::from_str(overlay).unwrap();
        let merged = deep_merge(base_val, overlay_val);

        assert_eq!(merged["listen"]["dns"]["port"].as_u64().unwrap(), 5353);
        assert!(merged["logging"]["stdout"]["enabled"].as_bool().unwrap());
    }

    #[test]
    fn empty_overlay_gets_full_base() {
        let base = "listen:\n  dns:\n    port: 53\n";
        let overlay = "{}";

        let base_val: Value = serde_yaml::from_str(base).unwrap();
        let overlay_val: Value = serde_yaml::from_str(overlay).unwrap();
        let merged = deep_merge(base_val, overlay_val);

        assert_eq!(merged["listen"]["dns"]["port"].as_u64().unwrap(), 53);
    }

    #[test]
    fn extra_user_keys_preserved() {
        let base = "listen:\n  dns:\n    port: 53\n";
        let overlay = "listen:\n  dns:\n    port: 53\ncustom_key: custom_value\n";

        let base_val: Value = serde_yaml::from_str(base).unwrap();
        let overlay_val: Value = serde_yaml::from_str(overlay).unwrap();
        let merged = deep_merge(base_val, overlay_val);

        assert_eq!(merged["custom_key"].as_str().unwrap(), "custom_value");
    }

    #[test]
    fn merge_with_example_produces_valid_yaml() {
        let user = "listen:\n  dns:\n    enabled: true\n    port: 5353\n";
        let result = merge_with_example(user);
        assert!(result.is_ok(), "merge should succeed: {:?}", result.err());
        let merged = result.unwrap();
        assert!(merged.contains("5353"), "user port should be in output");
        // Example defaults for sections not in user config should be present.
        assert!(
            merged.contains("blocklists"),
            "blocklists section should be filled from example"
        );
    }

    #[test]
    fn merge_with_example_user_blocklists_replace() {
        let user = "blocklists:\n  - my_list:\n      url: http://my.list\n      enabled: true\n";
        let result = merge_with_example(user).unwrap();
        let merged: Value = serde_yaml::from_str(&result).unwrap();
        let lists = merged["blocklists"].as_sequence().unwrap();
        // User's list should replace example lists entirely.
        assert_eq!(lists.len(), 1);
    }

    #[test]
    fn legacy_address_key_normalized_to_addresses() {
        let user = "listen:\n  dns:\n    enabled: true\n    address: \"0.0.0.0\"\n    port: 53\n";
        let result = merge_with_example(user).unwrap();
        let merged: Value = serde_yaml::from_str(&result).unwrap();
        let dns = &merged["listen"]["dns"];
        // Legacy `address` key must not appear in output.
        assert!(
            dns.get("address").is_none(),
            "legacy 'address' key should be removed after merge"
        );
        // Canonical `addresses` key must be present as a list.
        let addrs = dns["addresses"]
            .as_sequence()
            .expect("addresses should be a sequence");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].as_str().unwrap(), "0.0.0.0");
    }

    #[test]
    fn both_address_and_addresses_keeps_only_addresses() {
        let user = "listen:\n  dns:\n    enabled: true\n    address: \"127.0.0.1\"\n    addresses:\n      - \"0.0.0.0\"\n    port: 53\n";
        let result = merge_with_example(user).unwrap();
        let merged: Value = serde_yaml::from_str(&result).unwrap();
        let dns = &merged["listen"]["dns"];
        assert!(
            dns.get("address").is_none(),
            "legacy 'address' key should be removed when both are present"
        );
        let addrs = dns["addresses"].as_sequence().unwrap();
        assert_eq!(addrs[0].as_str().unwrap(), "0.0.0.0");
    }
}
