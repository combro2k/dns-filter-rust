use std::fmt;
use std::path::Path;

/// A loaded WASM plugin instance.
#[derive(Debug)]
pub struct WasmPlugin {
    pub name: String,
    pub enabled: bool,
}

/// Manages the lifecycle of all loaded WASM plugins.
pub struct WasmPluginRuntime {
    plugins: Vec<WasmPlugin>,
}

impl WasmPluginRuntime {
    /// Create an empty runtime with no plugins loaded.
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Load a WASM plugin from the given file path.
    pub fn load_plugin(path: &Path, name: &str) -> Result<WasmPlugin, PluginLoadError> {
        // TODO: Implement wasmtime-based plugin loading.
        let _ = (path, name);
        Err(PluginLoadError::NotImplemented)
    }

    /// Return the number of loaded plugins.
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }
}

impl Default for WasmPluginRuntime {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur when loading a WASM plugin.
#[derive(Debug)]
pub enum PluginLoadError {
    /// Plugin system is not yet implemented.
    NotImplemented,
    /// The plugin file could not be read.
    IoError(std::io::Error),
    /// The WASM module failed to compile or instantiate.
    CompileError(String),
    /// The plugin does not export the required ABI functions.
    MissingExport(String),
}

impl fmt::Display for PluginLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented => write!(f, "WASM plugin system is not yet implemented"),
            Self::IoError(e) => write!(f, "failed to read plugin file: {e}"),
            Self::CompileError(e) => write!(f, "failed to compile WASM module: {e}"),
            Self::MissingExport(name) => {
                write!(f, "plugin missing required export: {name}")
            }
        }
    }
}

impl std::error::Error for PluginLoadError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_starts_empty() {
        let rt = WasmPluginRuntime::new();
        assert_eq!(rt.plugin_count(), 0);
    }

    #[test]
    fn load_plugin_returns_not_implemented() {
        let result = WasmPluginRuntime::load_plugin(Path::new("/fake.wasm"), "test");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not yet implemented"));
    }
}
