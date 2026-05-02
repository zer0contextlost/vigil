use serde_json::Value;
use std::path::Path;

use crate::envelope::Envelope;

/// Must match `vigil_plugin::ABI_VERSION` in the plugin SDK.
/// Bump this whenever `VigilPlugin`, `Envelope`, or the FFI contract changes.
pub const ABI_VERSION: u32 = 1;

/// rustc version vigil-core was compiled with, baked in by build.rs.
pub const RUSTC_VERSION: &str = env!("VIGIL_RUSTC_VERSION");

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
    /// Plugins built with `vigil-plugin` and [`declare_plugin!`] are loaded safely:
    /// ABI version and rustc version are checked before instantiation, so a mismatch
    /// fails with a clear error rather than undefined behavior.
    pub fn load_from_file(&mut self, path: &Path) -> anyhow::Result<()> {
        unsafe {
            let lib = libloading::Library::new(path)
                .map_err(|e| anyhow::anyhow!("cannot load plugin {}: {}", path.display(), e))?;

            // --- ABI version check ---
            let abi_fn: std::result::Result<
                libloading::Symbol<unsafe extern "C" fn() -> u32>,
                _,
            > = lib.get(b"vigil_plugin_abi_version\0");
            if let Ok(abi_fn) = abi_fn {
                let plugin_abi = abi_fn();
                if plugin_abi != ABI_VERSION {
                    anyhow::bail!(
                        "ABI mismatch loading {}: plugin ABI v{}, host ABI v{}. \
                         Rebuild your plugin against vigil-plugin v{}.",
                        path.display(),
                        plugin_abi,
                        ABI_VERSION,
                        env!("CARGO_PKG_VERSION"),
                    );
                }
            }

            // --- rustc version check ---
            let rustc_fn: std::result::Result<
                libloading::Symbol<unsafe extern "C" fn() -> *const std::os::raw::c_char>,
                _,
            > = lib.get(b"vigil_plugin_rustc_version\0");
            if let Ok(rustc_fn) = rustc_fn {
                let ptr = rustc_fn();
                if !ptr.is_null() {
                    let plugin_rustc = std::ffi::CStr::from_ptr(ptr).to_string_lossy();
                    if plugin_rustc != RUSTC_VERSION {
                        anyhow::bail!(
                            "rustc mismatch loading {}: plugin built with {}, host built with {}. \
                             dyn VigilPlugin vtable layout is unstable across rustc versions; \
                             rebuild both with the same toolchain.",
                            path.display(),
                            plugin_rustc,
                            RUSTC_VERSION,
                        );
                    }
                }
            }

            // --- instantiate ---
            let create: libloading::Symbol<unsafe extern "C" fn() -> *mut Box<dyn VigilPlugin>> =
                lib.get(b"vigil_plugin_create\0").map_err(|e| {
                    anyhow::anyhow!(
                        "vigil_plugin_create not found in {}: {}. \
                         Did you use declare_plugin!() in your plugin?",
                        path.display(),
                        e
                    )
                })?;

            let raw = std::panic::catch_unwind(|| create()).map_err(|_| {
                anyhow::anyhow!(
                    "plugin {} panicked during vigil_plugin_create",
                    path.display()
                )
            })?;

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
