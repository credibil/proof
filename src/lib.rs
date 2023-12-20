pub use vercre_didcore::{test_utils, DidDocument, Patch, Registrar, Resolver, Service};

#[cfg(feature = "azure-kv")]
pub use vercre_azurekv;

#[cfg(feature = "didion")]
pub use vercre_didion;

#[cfg(feature = "didkey")]
pub use vercre_didkey;

#[cfg(feature = "didweb")]
pub use vercre_didweb::web::WebRegistrar;
