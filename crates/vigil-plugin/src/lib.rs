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
/// use vigil_plugin::{declare_plugin, PluginContext, PluginDecision, VigilPlugin, Envelope, Value};
///
/// struct MyPlugin;
/// impl VigilPlugin for MyPlugin {
///     fn name(&self) -> &str { "my-plugin" }
///
///     fn on_alert(&self, ctx: &PluginContext, label: &str, detail: &Value) {
///         eprintln!("[{}] session={} {}", label, ctx.session_id, detail);
///     }
///
///     fn on_tool_call(&self, _ctx: &PluginContext, tool_name: &str, _input: &Value) -> PluginDecision {
///         if tool_name == "Bash" {
///             PluginDecision::Deny("blocked by my-plugin".into())
///         } else {
///             PluginDecision::Allow
///         }
///     }
/// }
/// declare_plugin!(MyPlugin);
/// ```

pub use vigil_core::{Envelope, PluginContext, PluginDecision, VigilPlugin};
pub use serde_json::Value;

/// ABI version. Bumped whenever `VigilPlugin`, `PluginContext`, `PluginDecision`,
/// `Envelope`, or the FFI contract changes in a breaking way.
pub const ABI_VERSION: u32 = 2;

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
