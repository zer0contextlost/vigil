use serde_json::Value;
use std::path::Path;

use crate::envelope::Envelope;

/// Implement this trait to receive vigil events and alerts.
///
/// # Usage
///
/// Add `vigil-core` to your crate's dependencies, implement `VigilPlugin`,
/// then register your plugin with `PluginHost::add`. See the vigil-cli
/// `run_agent` function for where `PluginHost` is constructed.
///
/// # Threading
///
/// All methods are called from within an async tokio task. Implementations
/// must not block (no blocking I/O, no `std::thread::sleep`). Spawn a
/// `tokio::task` if you need async work.
pub trait VigilPlugin: Send + Sync {
    /// Called for every event that reaches the TUI (post-filter).
    fn on_event(&self, _envelope: &Envelope) {}

    /// Called whenever vigil emits an alert.
    ///
    /// `label` is one of: BURN LOOP EXFL DENY COST DURA TOUT WAPPR PII
    fn on_alert(&self, _label: &str, _session_id: &str, _detail: &Value) {}
}

/// Holds all registered plugins and fans out calls to each.
#[derive(Default)]
pub struct PluginHost {
    plugins: Vec<Box<dyn VigilPlugin>>,
}

impl PluginHost {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, plugin: Box<dyn VigilPlugin>) {
        self.plugins.push(plugin);
    }

    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Fan out an event to every registered plugin.
    pub fn dispatch_event(&self, envelope: &Envelope) {
        for p in &self.plugins {
            p.on_event(envelope);
        }
    }

    /// Fan out an alert to every registered plugin.
    pub fn dispatch_alert(&self, label: &str, session_id: &str, detail: &Value) {
        for p in &self.plugins {
            p.on_alert(label, session_id, detail);
        }
    }

    /// Load a plugin from a shared library (.dll / .so / .dylib).
    ///
    /// The library must export a C-ABI function with this exact signature:
    /// ```c
    /// // Rust: pub extern "C" fn vigil_plugin_create() -> *mut Box<dyn VigilPlugin>
    /// ```
    /// The returned pointer must be heap-allocated via `Box::into_raw(Box::new(plugin))`.
    /// vigil takes ownership and will free it.
    ///
    /// **Compatibility note**: plugin and host must be compiled with the same Rust
    /// toolchain and vigil-core version — `dyn VigilPlugin` vtable layout is not stable
    /// across compiler versions.
    pub fn load_from_file(&mut self, path: &Path) -> anyhow::Result<()> {
        unsafe {
            let lib = libloading::Library::new(path)
                .map_err(|e| anyhow::anyhow!("cannot load plugin {}: {}", path.display(), e))?;
            let create: libloading::Symbol<unsafe extern "C" fn() -> *mut Box<dyn VigilPlugin>> =
                lib.get(b"vigil_plugin_create\0")
                    .map_err(|e| anyhow::anyhow!("symbol vigil_plugin_create not found in {}: {}", path.display(), e))?;
            let raw = create();
            if raw.is_null() {
                anyhow::bail!("plugin {} returned null from vigil_plugin_create", path.display());
            }
            let plugin = *Box::from_raw(raw);
            // Leak the Library so it lives as long as the plugin.
            std::mem::forget(lib);
            self.plugins.push(plugin);
            Ok(())
        }
    }
}
