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
/// use vigil_plugin::{declare_plugin, VigilPlugin, Envelope};
///
/// struct MyPlugin;
/// impl VigilPlugin for MyPlugin {
///     fn on_alert(&self, label: &str, session_id: &str, detail: &vigil_plugin::Value) {
///         eprintln!("[{}] {}", label, detail);
///     }
/// }
/// declare_plugin!(MyPlugin);
/// ```

pub use vigil_core::{Envelope, VigilPlugin};
pub use serde_json::Value;

/// ABI version. Bumped whenever `VigilPlugin`, `Envelope`, or the FFI contract changes
/// in a breaking way. Plugin and host must agree or load is refused with a clear error.
pub const ABI_VERSION: u32 = 1;

/// The rustc version vigil-plugin was compiled with, baked in at build time.
pub const RUSTC_VERSION: &str = env!("VIGIL_RUSTC_VERSION");

/// Declare your plugin's entry point. Pass the constructor expression for your
/// type — it must implement [`VigilPlugin`].
///
/// This macro generates all the required C-ABI exports (`vigil_plugin_create`,
/// `vigil_plugin_abi_version`, `vigil_plugin_rustc_version`) so vigil can load,
/// version-check, and instantiate your plugin safely.
///
/// # Example
/// ```ignore
/// declare_plugin!(MyPlugin::new());
/// // or with struct literal syntax:
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
            concat!(env!("VIGIL_RUSTC_VERSION"), "\0").as_ptr() as *const std::os::raw::c_char
        }
    };
}
