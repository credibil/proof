//! Key management. This module provides a trait that can be implemented for creating and rolling
//! over cryptographic keys for use in DID operations or general signing and verification.

use crate::keys::{Jwk, KeyOperation};
use crate::Result;

/// Key generation and storage provider. The `self` reference allows for configuration information
/// such as key store location and credentials.
#[allow(async_fn_in_trait)]
pub trait KeyRing {
    /// Get the currently active public key for the specified key operation. If there is no such key
    /// active key in the key ring, attempt to find the next most recent previous version of that
    /// key.
    ///
    /// # Arguments
    ///
    /// * `op` - The key operation type.
    ///
    /// # Returns
    ///
    /// A [`PublicKeyJwk`] containing the public key for the specified key operation or an error if
    /// the key could not be found or some other error occurred.
    async fn active_key(&self, op: &KeyOperation) -> Result<Jwk>;

    /// Get the public key for the next key pair that will be used for DID operations of the
    /// specified type.
    ///
    /// # Arguments
    ///
    /// * `op` - The key operation type.
    ///
    /// # Returns
    ///
    /// A [`PublicKeyJwk`] containing the public key for the specified key operation or an error if
    /// none could be created.
    async fn next_key(&self, op: &KeyOperation) -> Result<Jwk>;

    /// The `KeyRing` is asynchronous and needs to be thread-safe so we cannot mutate the `KeyRing`
    /// structure itself to manage interim key information. Commit will be called following
    /// a successful DID operation and can be used to save newly generated "next" keys to a key
    /// store and make them current. A no-op default is provided if your implementation does not
    /// need a commit.
    async fn commit(&self) -> Result<()> {
        async move { Ok(()) }.await
    }
}
