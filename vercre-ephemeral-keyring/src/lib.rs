//! `KeyRing` and `Signer` implementations for keys that are generated and used in-memory and
//! disappear when out of scope.

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

use vercre_didcore::{Jwk, Result};

mod keyring;
mod secp256k1;
mod signer;

pub use keyring::EphemeralKeyRing;
pub use signer::EphemeralSigner;

/// Asymmetric key pair.
#[derive(Clone, Debug)]
pub struct AsymmetricKey<P, S> {
    /// Public key for an asymmetric key pair.
    pub public_key: P,
    /// Secret key for an asymmetric key pair.
    pub secret_key: Option<S>,
}

/// A supported key type needs to be able to generate a key pair and express itself as a JWK.
pub trait KeyPair {
    /// Generate a new key pair.
    fn generate() -> Result<Self> where Self: Sized;

    /// Express the public key as a JWK.
    fn to_jwk(&self) -> Result<Jwk>;
}
