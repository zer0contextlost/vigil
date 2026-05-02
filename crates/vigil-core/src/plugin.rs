use serde_json::Value;
use std::path::{Path, PathBuf};

use crate::envelope::Envelope;

/// ABI version. Bump whenever `VigilPlugin`, `PluginContext`, `AlertLabel`,
/// `AlertDetail`, `PluginDecision`, `Envelope`, or the FFI contract changes.
pub const ABI_VERSION: u32 = 3;

/// rustc version vigil-core was compiled with, baked in by build.rs.
pub const RUSTC_VERSION: &str = env!("VIGIL_RUSTC_VERSION");

// ---------------------------------------------------------------------------
// AlertLabel — strongly-typed alert discriminant
// ---------------------------------------------------------------------------

/// Every alert vigil can fire. Passed to `on_alert` instead of a raw string
/// so plugin authors get exhaustive match checking and no typo risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertLabel {
    BurnRate,
    Loop,
    Exfil,
    Deny,
    Cost,
    Duration,
    Timeout,
    WriteApproval,
    Pii,
}

impl AlertLabel {
    /// The short code used in the TUI and NDJSON logs (e.g. `"BURN"`).
    pub fn code(self) -> &'static str {
        match self {
            Self::BurnRate     => "BURN",
            Self::Loop         => "LOOP",
            Self::Exfil        => "EXFL",
            Self::Deny         => "DENY",
            Self::Cost         => "COST",
            Self::Duration     => "DURA",
            Self::Timeout      => "TOUT",
            Self::WriteApproval => "WAPPR",
            Self::Pii          => "PII",
        }
    }

    /// Parse a code string back to an `AlertLabel`. Returns `None` for
    /// unrecognised codes (forward-compat: treat as unknown, don't panic).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "BURN"  => Some(Self::BurnRate),
            "LOOP"  => Some(Self::Loop),
            "EXFL"  => Some(Self::Exfil),
            "DENY"  => Some(Self::Deny),
            "COST"  => Some(Self::Cost),
            "DURA"  => Some(Self::Duration),
            "TOUT"  => Some(Self::Timeout),
            "WAPPR" => Some(Self::WriteApproval),
            "PII"   => Some(Self::Pii),
            _       => None,
        }
    }

    /// Deserialise the raw `detail` `Value` into a typed `AlertDetail`.
    pub fn parse_detail(self, detail: &Value) -> AlertDetail {
        AlertDetail::from_label(self, detail)
    }
}

impl std::fmt::Display for AlertLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

// ---------------------------------------------------------------------------
// Typed alert detail structs
// ---------------------------------------------------------------------------

pub mod alert {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct BurnRate {
        pub rate_per_min_usd: f64,
        pub projected_total_usd: f64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Loop {
        pub tool_name: String,
        pub repeat_count: u32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Exfil {
        pub source: String,
        pub matches: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Deny {
        pub tool_name: String,
        pub policy: Option<String>,
        pub reason: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Cost {
        pub threshold_usd: f64,
        pub session_cost_usd: f64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Duration {
        pub elapsed_mins: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Timeout {
        pub tool_name: String,
        pub elapsed_secs: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct WriteApproval {
        pub path: String,
        pub risk: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Pii {
        pub kind: String,
        pub snippet: String,
    }
}

/// Typed wrapper around the alert detail payload. Prefer matching on this
/// over hand-parsing `&Value`. Fall back to `Unknown` for future alert types.
#[derive(Debug, Clone)]
pub enum AlertDetail {
    BurnRate(alert::BurnRate),
    Loop(alert::Loop),
    Exfil(alert::Exfil),
    Deny(alert::Deny),
    Cost(alert::Cost),
    Duration(alert::Duration),
    Timeout(alert::Timeout),
    WriteApproval(alert::WriteApproval),
    Pii(alert::Pii),
    /// Catch-all for unrecognised or future alert types.
    Unknown(Value),
}

impl AlertDetail {
    pub fn from_label(label: AlertLabel, v: &Value) -> Self {
        fn try_parse<T: serde::de::DeserializeOwned>(
            v: &Value,
            wrap: fn(T) -> AlertDetail,
        ) -> Option<AlertDetail> {
            serde_json::from_value(v.clone()).ok().map(wrap)
        }
        match label {
            AlertLabel::BurnRate     => try_parse(v, AlertDetail::BurnRate),
            AlertLabel::Loop         => try_parse(v, AlertDetail::Loop),
            AlertLabel::Exfil        => try_parse(v, AlertDetail::Exfil),
            AlertLabel::Deny         => try_parse(v, AlertDetail::Deny),
            AlertLabel::Cost         => try_parse(v, AlertDetail::Cost),
            AlertLabel::Duration     => try_parse(v, AlertDetail::Duration),
            AlertLabel::Timeout      => try_parse(v, AlertDetail::Timeout),
            AlertLabel::WriteApproval => try_parse(v, AlertDetail::WriteApproval),
            AlertLabel::Pii          => try_parse(v, AlertDetail::Pii),
        }
        .unwrap_or_else(|| AlertDetail::Unknown(v.clone()))
    }

    /// Convert back to a raw `Value` for serialisation or legacy code.
    pub fn as_value(&self) -> Value {
        match self {
            Self::BurnRate(v)      => serde_json::to_value(v).unwrap_or_default(),
            Self::Loop(v)          => serde_json::to_value(v).unwrap_or_default(),
            Self::Exfil(v)         => serde_json::to_value(v).unwrap_or_default(),
            Self::Deny(v)          => serde_json::to_value(v).unwrap_or_default(),
            Self::Cost(v)          => serde_json::to_value(v).unwrap_or_default(),
            Self::Duration(v)      => serde_json::to_value(v).unwrap_or_default(),
            Self::Timeout(v)       => serde_json::to_value(v).unwrap_or_default(),
            Self::WriteApproval(v) => serde_json::to_value(v).unwrap_or_default(),
            Self::Pii(v)           => serde_json::to_value(v).unwrap_or_default(),
            Self::Unknown(v)       => v.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// PluginContext
// ---------------------------------------------------------------------------

/// Context passed to every plugin hook. Carries per-session and per-plugin
/// state without widening each method signature.
#[derive(Clone)]
pub struct PluginContext {
    pub session_id: uuid::Uuid,
    /// Per-plugin config/data directory: `~/.vigil/plugins/<plugin-name>/`
    /// Created on first dispatch if it doesn't exist.
    pub config_dir: PathBuf,
    /// Version of the running vigil binary.
    pub host_version: &'static str,
}

// ---------------------------------------------------------------------------
// PluginDecision
// ---------------------------------------------------------------------------

/// Decision returned by `on_tool_call`. All plugins are consulted in
/// registration order; the first `Deny` wins.
#[derive(Debug, Clone)]
pub enum PluginDecision {
    Allow,
    Deny(String),
}

// ---------------------------------------------------------------------------
// VigilPlugin trait (async)
// ---------------------------------------------------------------------------

/// Implement this trait to extend vigil with custom logic.
///
/// All methods are async — you can freely `.await` I/O without blocking the
/// event loop. Methods have default no-op implementations so you only
/// override what you need.
///
/// Use [`declare_plugin!`] from the `vigil-plugin` SDK crate to export your
/// implementation as a shared library.
#[async_trait::async_trait]
pub trait VigilPlugin: Send + Sync {
    /// Human-readable name — shown in `vigil plugins list` and used to
    /// derive the per-plugin config directory.
    fn name(&self) -> &str { "unnamed" }

    /// Called for every event that passes the filter (post-policy).
    async fn on_event(&self, _ctx: &PluginContext, _envelope: &Envelope) {}

    /// Called whenever vigil fires an alert.
    async fn on_alert(&self, _ctx: &PluginContext, _label: AlertLabel, _detail: &Value) {}

    /// Called for every tool call that the built-in policy engine allows.
    /// Return `PluginDecision::Deny(reason)` to block the call; the agent
    /// receives an HTTP 403 with your reason string and a DENY alert fires.
    async fn on_tool_call(
        &self,
        _ctx: &PluginContext,
        _tool_name: &str,
        _input: &Value,
    ) -> PluginDecision {
        PluginDecision::Allow
    }
}

// ---------------------------------------------------------------------------
// LoadedPlugin — keeps the Library alive alongside its plugin
// ---------------------------------------------------------------------------

struct LoadedPlugin {
    plugin: Box<dyn VigilPlugin>,
    /// Keeps the shared library mapped in memory for as long as the plugin lives.
    /// `None` for in-process plugins added via `PluginHost::add`.
    _lib: Option<libloading::Library>,
}

// ---------------------------------------------------------------------------
// PluginHost
// ---------------------------------------------------------------------------

/// Holds all registered plugins and fans out calls to each.
#[derive(Default)]
pub struct PluginHost {
    plugins: Vec<LoadedPlugin>,
}

impl PluginHost {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an in-process plugin (no shared library involved).
    pub fn add(&mut self, plugin: Box<dyn VigilPlugin>) {
        self.plugins.push(LoadedPlugin { plugin, _lib: None });
    }

    pub fn is_empty(&self) -> bool { self.plugins.is_empty() }
    pub fn len(&self) -> usize { self.plugins.len() }

    /// Fan out an event to every plugin. Each plugin receives a context with
    /// `config_dir` pointing to its own per-plugin subdirectory.
    pub async fn dispatch_event(&self, ctx: &PluginContext, envelope: &Envelope) {
        for lp in &self.plugins {
            let pctx = per_plugin_ctx(ctx, lp.plugin.name());
            lp.plugin.on_event(&pctx, envelope).await;
        }
    }

    /// Fan out an alert to every plugin.
    pub async fn dispatch_alert(&self, ctx: &PluginContext, label: AlertLabel, detail: &Value) {
        for lp in &self.plugins {
            let pctx = per_plugin_ctx(ctx, lp.plugin.name());
            lp.plugin.on_alert(&pctx, label, detail).await;
        }
    }

    /// Consult every plugin about a tool call. Returns the first `Deny`, or
    /// `Allow` if all plugins approve.
    pub async fn dispatch_tool_call(
        &self,
        ctx: &PluginContext,
        tool_name: &str,
        input: &Value,
    ) -> PluginDecision {
        for lp in &self.plugins {
            let pctx = per_plugin_ctx(ctx, lp.plugin.name());
            match lp.plugin.on_tool_call(&pctx, tool_name, input).await {
                PluginDecision::Allow => continue,
                deny => return deny,
            }
        }
        PluginDecision::Allow
    }

    /// Load a plugin from a shared library (.dll / .so / .dylib).
    ///
    /// Checks ABI version and rustc version before instantiation so a mismatch
    /// fails with a clear error rather than undefined behavior. The Library is
    /// stored alongside the plugin so it stays mapped for the plugin's lifetime.
    pub fn load_from_file(&mut self, path: &Path) -> anyhow::Result<()> {
        let lp = Self::load_file_inner(path)?;
        self.plugins.push(lp);
        Ok(())
    }

    /// Validate a shared library without loading it permanently.
    /// Prints a status line for each check step and returns Ok(plugin_name).
    pub fn check_file(path: &Path) -> anyhow::Result<String> {
        let lp = Self::load_file_inner(path)?;
        Ok(lp.plugin.name().to_string())
    }

    fn load_file_inner(path: &Path) -> anyhow::Result<LoadedPlugin> {
        unsafe {
            let lib = libloading::Library::new(path)
                .map_err(|e| anyhow::anyhow!("cannot load {}: {}", path.display(), e))?;

            // ABI version check
            let abi_fn: std::result::Result<
                libloading::Symbol<unsafe extern "C" fn() -> u32>, _,
            > = lib.get(b"vigil_plugin_abi_version\0");
            if let Ok(abi_fn) = abi_fn {
                let plugin_abi = abi_fn();
                if plugin_abi != ABI_VERSION {
                    anyhow::bail!(
                        "ABI mismatch in {}: plugin v{}, host v{}. \
                         Rebuild against vigil-plugin v{}.",
                        path.display(), plugin_abi, ABI_VERSION,
                        env!("CARGO_PKG_VERSION"),
                    );
                }
            }

            // rustc version check
            let rustc_fn: std::result::Result<
                libloading::Symbol<unsafe extern "C" fn() -> *const std::os::raw::c_char>, _,
            > = lib.get(b"vigil_plugin_rustc_version\0");
            if let Ok(rustc_fn) = rustc_fn {
                let ptr = rustc_fn();
                if !ptr.is_null() {
                    let plugin_rustc = std::ffi::CStr::from_ptr(ptr).to_string_lossy();
                    if plugin_rustc != RUSTC_VERSION {
                        anyhow::bail!(
                            "rustc mismatch in {}: plugin {}, host {}. \
                             Rebuild both with the same toolchain.",
                            path.display(), plugin_rustc, RUSTC_VERSION,
                        );
                    }
                }
            }

            // Instantiate
            let create: libloading::Symbol<unsafe extern "C" fn() -> *mut Box<dyn VigilPlugin>> =
                lib.get(b"vigil_plugin_create\0").map_err(|e| {
                    anyhow::anyhow!(
                        "vigil_plugin_create not found in {}: {}. \
                         Did you use declare_plugin!()?",
                        path.display(), e,
                    )
                })?;

            let raw = std::panic::catch_unwind(|| create()).map_err(|_| {
                anyhow::anyhow!("plugin {} panicked during vigil_plugin_create", path.display())
            })?;

            if raw.is_null() {
                anyhow::bail!("plugin {} returned null from vigil_plugin_create", path.display());
            }
            let plugin = *Box::from_raw(raw);
            Ok(LoadedPlugin { plugin, _lib: Some(lib) })
        }
    }
}

fn per_plugin_ctx(base: &PluginContext, plugin_name: &str) -> PluginContext {
    PluginContext {
        session_id: base.session_id,
        config_dir: base.config_dir.join(plugin_name),
        host_version: base.host_version,
    }
}
