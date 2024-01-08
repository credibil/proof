use vercre_didcore::{error::Err, KeyOperation, Result, Signer, Algorithm};

use crate::keyring::EphemeralKeyRing;

/// Signer using an ephemeral keyring.
pub struct EphemeralSigner {
    keyring: EphemeralKeyRing,
}

/// Constructor and methods for `EphemeralSigner`.
impl EphemeralSigner {
    /// Create a new `EphemeralSigner` instance.
    ///
    /// # Arguments
    ///
    /// * `keyring` - The keyring to use for signing.
    #[must_use]
    pub fn new(keyring: EphemeralKeyRing) -> Self {
        Self { keyring }
    }
}

/// Implementation of the [`Signer`] trait for ephemeral keys.
#[allow(async_fn_in_trait)]
impl Signer for EphemeralSigner {
    /// Type of signature algorithm.
    fn supported_algorithms(&self) -> Vec<Algorithm> {
        vec![Algorithm::Secp256k1]
    }

    /// Sign the provided message bytestring using `Self` and the key stored for the specified key
    /// operation.
    /// 
    /// # Arguments
    /// 
    /// * `msg` - The message to sign.
    /// * `op` - The key operation to use for signing.
    /// * `alg` - The algorithm to use for signing.
    /// 
    /// # Returns
    /// 
    /// * The signed message as a byte vector or an error if the message could not be signed.
    /// * The key ID that can be used to look up the public key. (This is provided by the
    /// underlying keyring.)
    async fn try_sign_op(
        &self,
        _msg: &[u8],
        _op: &KeyOperation,
        _alg: Option<Algorithm>,
    ) -> Result<(Vec<u8>, Option<String>)> {
        Err(Err::NotImplemented.into())
    }

    /// Verify the provided signature against the provided message bytestring using `Self` and the
    /// key stored for the `KeyOperation::Sign` key operation.
    ///
    /// # Arguments
    ///
    /// * `data` - The message to verify the signature for.
    /// * `signature` - The signature to verify.
    /// * `verification_method` - The verification method such as a key ID or URL that can be used
    /// to look up the public key, or a serialized public key itself.
    ///
    /// # Returns
    ///
    /// An error if the signature is invalid or the message could not be verified.
    async fn verify(
        &self,
        _data: &[u8],
        _signature: &[u8],
        _verification_method: Option<&str>,
    ) -> Result<()> {
        Err(Err::NotImplemented.into())
    }
}