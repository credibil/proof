use did_core::error::Err;
use did_core::{tracerr, Algorithm, KeyOperation, Result, Signer};

use crate::keyring::EphemeralKeyRing;
use crate::KeyPair;

/// Signer using an ephemeral keyring.
#[allow(clippy::module_name_repetitions)]
pub struct EphemeralSigner<K>
where
    K: KeyPair + Send + Sync,
{
    keyring: EphemeralKeyRing<K>,
}

/// Constructor and methods for `EphemeralSigner`.
impl<K> EphemeralSigner<K>
where
    K: KeyPair + Send + Sync,
{
    /// Create a new `EphemeralSigner` instance.
    ///
    /// # Arguments
    ///
    /// * `keyring` - The keyring to use for signing.
    #[must_use]
    pub fn new(keyring: EphemeralKeyRing<K>) -> Self {
        Self { keyring }
    }
}

/// Implementation of the [`Signer`] trait for ephemeral keys.
impl<K> Signer for EphemeralSigner<K>
where
    K: KeyPair + Send + Sync,
{
    /// Type of signature algorithm.
    fn supported_algorithms(&self) -> Vec<Algorithm> {
        vec![K::key_type()]
    }

    /// Sign the provided message bytestring using `Self` and the key stored for the specified key
    /// operation.
    ///
    /// # Arguments
    ///
    /// * `msg` - The message to sign.
    /// * `op` - The key operation to use for signing.
    /// * `alg` - The algorithm to use for signing. This trait parameter is unused. The type of
    /// key-pair `K` is used to determine the algorithm.
    ///
    /// # Returns
    ///
    /// * The signed message as a byte vector or an error if the message could not be signed.
    /// * The key ID that can be used to look up the public key. (This is provided by the
    /// underlying keyring.)
    async fn try_sign_op(
        &self, msg: &[u8], op: &KeyOperation, alg: Option<Algorithm>,
    ) -> Result<(Vec<u8>, Option<String>)> {
        if alg.is_some() {
            tracerr!(Err::InvalidConfig, "algorithm should be None (inferred by type)");
        }
        let current_keys =
            self.keyring.current_keys.lock().expect("lock on current_keys mutex failed");
        if !current_keys.contains_key(op) {
            tracerr!(Err::KeyNotFound, "attempt to sign with key that does not exist");
        }
        let key = current_keys[op].clone();
        let payload = key.sign(msg)?;
        Ok((payload, None))
    }

    /// Verify the provided signature against the provided message bytestring using `Self` and the
    /// key stored for the `KeyOperation::Sign` key operation.
    ///
    /// # Arguments
    ///
    /// * `data` - The message to verify the signature for.
    /// * `signature` - The signature to verify.
    /// * `verification_method` - This is not supported for this keyring. If a value is supplied,
    /// an error is returned.
    ///
    /// # Returns
    ///
    /// An error if the signature is invalid or the message could not be verified.
    async fn verify(
        &self, data: &[u8], signature: &[u8], verification_method: Option<&str>,
    ) -> Result<()> {
        if verification_method.is_some() {
            tracerr!(Err::NotSupported, "verification method not supported");
        }
        let current_keys =
            self.keyring.current_keys.lock().expect("lock on current_keys mutex failed");
        if !current_keys.contains_key(&KeyOperation::Sign) {
            tracerr!(Err::KeyNotFound, "attempt to verify with key that does not exist");
        }
        let key = current_keys[&KeyOperation::Sign].clone();
        key.verify(data, signature)
    }
}

#[cfg(test)]
mod tests {

    use did_core::KeyRing;

    use super::*;
    use crate::keyring::EphemeralKeyRing;
    use crate::secp256k1::KeyPair as Secp256k1KeyPair;

    #[tokio::test]
    async fn test_signer() {
        let keyring = EphemeralKeyRing::<Secp256k1KeyPair>::new();
        keyring.next_key(&KeyOperation::Sign).await.unwrap();
        keyring.commit().await.unwrap();
        let signer = EphemeralSigner::new(keyring);
        let msg = b"Hello, world!";
        let (payload, _) = signer.try_sign_op(msg, &KeyOperation::Sign, None).await.unwrap();
        let parts = payload.split(|c| *c == b'.').collect::<Vec<&[u8]>>();
        assert_eq!(parts.len(), 3);
        let sig = parts[2];
        signer.verify(msg, &sig, None).await.expect("failed to verify");
    }
}
