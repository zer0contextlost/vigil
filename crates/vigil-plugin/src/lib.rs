/// vigil plugin SDK.
///
/// Add this crate to your plugin's dependencies:
/// ```toml
/// [lib]
/// crate-type = ["cdylib"]
///
/// [dependencies]
/// vigil-plugin = { git = "https://github.com/zer0contextlost/vigil" }
/// ```
///
/// Then implement [`VigilPlugin`] and export it with [`declare_plugin!`]:
/// ```ignore
/// use vigil_plugin::{async_trait, declare_plugin, AlertLabel, PluginContext, PluginDecision, VigilPlugin, Envelope, Value};
///
/// struct MyPlugin;
///
/// #[async_trait]
/// impl VigilPlugin for MyPlugin {
///     fn name(&self) -> &str { "my-plugin" }
///
///     async fn on_session_start(&self, ctx: &PluginContext) {
///         eprintln!("Session {} started", ctx.session_id);
///     }
///
///     async fn on_alert(&self, ctx: &PluginContext, label: AlertLabel, detail: &Value) {
///         eprintln!("[{}] session={} {}", label, ctx.session_id, detail);
///     }
///
///     async fn on_tool_call(&self, _ctx: &PluginContext, tool_name: &str, _input: &Value) -> PluginDecision {
///         if tool_name == "Bash" {
///             PluginDecision::Deny("blocked by my-plugin".into())
///         } else {
///             PluginDecision::Allow
///         }
///     }
/// }
/// declare_plugin!(MyPlugin);
/// ```
///
/// Other available hooks: `on_session_end`, `on_event`, `on_outbound_request`.

pub use vigil_core::{alert, AlertDetail, AlertLabel, Envelope, PluginContext, PluginDecision, VigilPlugin};
pub use serde_json::Value;
pub use async_trait::async_trait;

/// ABI version. Bumped whenever `VigilPlugin`, `PluginContext`, `PluginDecision`,
/// `AlertLabel`, `Envelope`, or the FFI contract changes in a breaking way.
///
/// **v4 is frozen for the 1.0 release.** Do NOT increment this constant without
/// a corresponding bump in `vigil-core/src/plugin.rs` and a CHANGELOG entry.
/// Incrementing ABI_VERSION invalidates all existing compiled plugins.
pub const ABI_VERSION: u32 = 4;

/// The rustc version vigil-plugin was compiled with, baked in at build time.
pub const RUSTC_VERSION: &str = env!("VIGIL_RUSTC_VERSION");

/// Declare your plugin's entry point. Pass the constructor expression for your
/// type — it must implement [`VigilPlugin`].
///
/// Generates all required C-ABI exports so vigil can load, version-check,
/// and instantiate your plugin safely. No `unsafe`, no `#[no_mangle]` in your code.
///
/// # Example
/// ```ignore
/// declare_plugin!(MyPlugin::new());
/// declare_plugin!(MyPlugin { field: value });
/// ```
#[macro_export]
macro_rules! declare_plugin {
    ($ctor:expr) => {
        #[doc(hidden)]
        #[no_mangle]
        pub extern "C" fn vigil_plugin_create() -> *mut Box<dyn $crate::VigilPlugin> {
            let plugin: Box<dyn $crate::VigilPlugin> = Box::new($ctor);
            Box::into_raw(Box::new(plugin))
        }

        #[doc(hidden)]
        #[no_mangle]
        pub extern "C" fn vigil_plugin_abi_version() -> u32 {
            $crate::ABI_VERSION
        }

        #[doc(hidden)]
        #[no_mangle]
        pub extern "C" fn vigil_plugin_rustc_version() -> *const std::os::raw::c_char {
            static VERSION_CSTR: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();
            VERSION_CSTR
                .get_or_init(|| {
                    std::ffi::CString::new($crate::RUSTC_VERSION).unwrap_or_default()
                })
                .as_ptr()
        }
    };
}
