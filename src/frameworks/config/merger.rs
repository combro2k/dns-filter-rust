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
    let base: Value = serde_yaml::from_str(EXAMPLE_CONFIG)
        .context("failed to parse embedded example config (this is a bug)")?;

    let overlay: Value =
        serde_yaml::from_str(user_config).context("failed to parse user config file")?;

    let merged = deep_merge(base, overlay);

    serde_yaml::to_string(&merged).context("failed to serialize merged config")
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
}
