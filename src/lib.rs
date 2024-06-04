#[cfg(feature = "azure-kv")]
pub use azure_kv;
pub use did_core::{
    test_utils, DidDocument, Patch, Registrar, Resolution, Resolver, Service, Signer,
};
#[cfg(feature = "did-ion")]
pub use did_ion::ion::Registrar as IonRegistrar;
#[cfg(feature = "did-jwk")]
pub use did_jwk::jwk::Registrar as JwkRegistrar;
#[cfg(feature = "did-web")]
pub use did_web::web::Registrar as WebRegistrar;
#[cfg(feature = "keyring")]
pub use keyring::{EphemeralKeyRing, EphemeralSigner, Secp256k1KeyPair};
