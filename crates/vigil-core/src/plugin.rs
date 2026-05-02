use serde_json::Value;
use std::path::{Path, PathBuf};

use crate::envelope::Envelope;

/// Must match `vigil_plugin::ABI_VERSION` in the plugin SDK.
/// Bump this whenever `VigilPlugin`, `Envelope`, or the FFI contract changes.
pub const ABI_VERSION: u32 = 2;

/// rustc version vigil-core was compiled with, baked in by build.rs.
pub const RUSTC_VERSION: &str = env!("VIGIL_RUSTC_VERSION");

/// Context passed to every plugin hook. Carries per-session state and
/// host metadata without widening each method signature.
#[derive(Clone)]
pub struct PluginContext {
    pub session_id: uuid::Uuid,
    /// Per-plugin config/data directory: `~/.vigil/plugins/<plugin-name>/`
    pub config_dir: PathBuf,
    /// Version of the running vigil binary.
    pub host_version: &'static str,
}

/// Decision returned by `on_tool_call`. All plugins are consulted in
/// registration order; the first `Deny` wins.
#[derive(Debug, Clone)]
pub enum PluginDecision {
    Allow,
    Deny(String),
}

/// Implement this trait to extend vigil with custom logic.
///
/// All methods have default no-op implementations so you only override what
/// you need. Methods are called from within an async tokio task — do not
/// block. Spawn a `tokio::task` for any I/O.
pub trait VigilPlugin: Send + Sync {
    /// Human-readable name used in log messages and `vigil plugins list`.
    fn name(&self) -> &str { "unnamed" }

    /// Called for every event that passes the filter (post-policy).
    fn on_event(&self, _ctx: &PluginContext, _envelope: &Envelope) {}

    /// Called whenever vigil fires an alert.
    /// `label` is one of: BURN LOOP EXFL DENY COST DURA TOUT WAPPR PII
    fn on_alert(&self, _ctx: &PluginContext, _label: &str, _detail: &Value) {}

    /// Called for every tool call that the built-in policy engine allows.
    /// Return `PluginDecision::Deny(reason)` to block the call; the agent
    /// receives an HTTP 403 with your reason string, and a DENY alert fires.
    fn on_tool_call(
        &self,
        _ctx: &PluginContext,
        _tool_name: &str,
        _input: &Value,
    ) -> PluginDecision {
        PluginDecision::Allow
    }
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

    pub fn dispatch_event(&self, ctx: &PluginContext, envelope: &Envelope) {
        for p in &self.plugins {
            p.on_event(ctx, envelope);
        }
    }

    pub fn dispatch_alert(&self, ctx: &PluginContext, label: &str, detail: &Value) {
        for p in &self.plugins {
            p.on_alert(ctx, label, detail);
        }
    }

    /// Consult every plugin about a tool call. Returns the first `Deny`, or
    /// `Allow` if all plugins approve.
    pub fn dispatch_tool_call(
        &self,
        ctx: &PluginContext,
        tool_name: &str,
        input: &Value,
    ) -> PluginDecision {
        for p in &self.plugins {
            match p.on_tool_call(ctx, tool_name, input) {
                PluginDecision::Allow => continue,
                deny => return deny,
            }
        }
        PluginDecision::Allow
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
            std::mem::forget(lib);
            self.plugins.push(plugin);
            Ok(())
        }
    }
}
