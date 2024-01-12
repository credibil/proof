pub use vercre_didcore::{
    test_utils, DidDocument, Patch, Registrar, Resolution, Resolver, Service, Signer,
};

#[cfg(feature = "azure-kv")]
pub use vercre_azurekv;

#[cfg(feature = "didion")]
pub use vercre_didion::ion::Registrar as IonRegistrar;

#[cfg(feature = "didjwk")]
pub use vercre_didjwk::jwk::Registrar as JwkRegistrar;

#[cfg(feature = "didweb")]
pub use vercre_didweb::web::Registrar as WebRegistrar;

#[cfg(feature = "ephemeral-keyring")]
pub use vercre_ephemeral_keyring::{EphemeralKeyRing, EphemeralSigner, Secp256k1KeyPair};
