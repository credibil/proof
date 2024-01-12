//! `KeyRing` and `Signer` implementations for keys that are generated and used in-memory and
//! disappear when out of scope.

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

use vercre_didcore::{Algorithm, Jwk, Result};

mod keyring;
mod secp256k1;
mod signer;

pub use keyring::EphemeralKeyRing;
pub use secp256k1::KeyPair as Secp256k1KeyPair;
pub use signer::EphemeralSigner;

/// Asymmetric key pair.
#[derive(Clone, Debug)]
pub struct AsymmetricKey<V, S> {
    /// Key for verifying.
    pub verifying_key: V,
    /// Secret key for signing.
    pub signing_key: Option<S>,
}

/// A supported key type needs to be able to generate a key pair and express itself as a JWK.
pub trait KeyPair {
    /// Declare the type of the algorithm used to generate a key pair.
    fn key_type() -> Algorithm;

    /// Generate a new key pair.
    ///
    /// # Returns
    ///
    /// A new key pair.
    ///
    /// # Errors
    ///
    /// An error should be returned if the key pair could not be generated.
    fn generate() -> Result<Self>
    where
        Self: Sized + Send + Sync;

    /// Express the public key as a JWK.
    ///
    /// # Returns
    ///
    /// The public key as a JWK.
    ///
    /// # Errors
    ///
    /// An error should be returned if the key could not be expressed as a JWK.
    fn to_jwk(&self) -> Result<Jwk>;

    /// Sign a message.
    ///
    /// # Arguments
    ///
    /// * `msg` - The message to sign.
    ///
    /// # Returns
    ///
    /// The signed message as a byte vector.
    ///
    /// # Errors
    ///
    /// An error should be returned if the message could not be signed.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>>;

    /// Verify a signature.
    ///
    /// # Arguments
    ///
    /// * `msg` - The signed message.
    /// * `sig` - The signature to verify.
    ///
    /// # Errors
    ///
    /// An error should be returned if the signature is invalid or the message could not be
    /// verified.
    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<()>;
}
