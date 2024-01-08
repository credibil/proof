//! Message signer and verifier trait. Intended to be used together with a [`KeyRing`], but can be
//! independent.

use crate::keys::{Algorithm, KeyOperation};
use crate::{error::Err, tracerr, Result};

/// Message signer. The trait uses methods so the assumption is the implementer of the trait will
/// have key information stored in the structure. How the data is manipulated before signing is not
/// specified and is up to the implementer. For most of the examples in the Credibil framework, a
/// header is pre-pended to the message and the two are encoded and hashed before signing. But this
/// is not necessary as long as the sign and verify methods are consistent.
#[allow(async_fn_in_trait)]
pub trait Signer {
    /// Type of key signatures supported by this signer.
    fn supported_algorithms(&self) -> Vec<Algorithm>;

    /// Reconcile the requested algorithm with the supported algorithms, returning a default if no
    /// algorithm is provided or an error if the requested algorithm is not supported. A default
    /// implementation is provided here that will just return the first configured algorithm as the
    /// default.
    fn algorithm(&self, alg: Option<Algorithm>) -> Result<Algorithm> {
        let my_algs = self.supported_algorithms();
        match alg {
            None => Ok(my_algs[0]),
            Some(alg) => {
                if my_algs.iter().any(|a| *a == alg) {
                    Ok(alg)
                } else {
                    tracerr!(
                        Err::UnsupportedAlgorithm,
                        "Unsupported signing algorithm: {}",
                        alg
                    );
                }
            }
        }
    }

    /// Sign the provided message bytestring using `Self`. The key stored for `KeyOperation::Sign`
    /// should be used. To sign a message using a different key, use the [`sign_op`] function.
    ///
    /// # Arguments
    ///
    /// * `msg` - The message to sign.
    /// * `alg` - The algorithm to use for signing. If the signer supports multiple
    /// algorithms, this parameter is used to select the algorithm to use. If unspecified, the
    /// signer can use a default.
    ///
    /// # Returns
    ///
    /// * Signed message as a byte vector or an error if the message could not be signed.
    /// * The verification method such as a key ID or URL that can be used to look up the public
    /// key, or a serialized public key itself.
    async fn try_sign(
        &self,
        msg: &[u8],
        alg: Option<Algorithm>,
    ) -> Result<(Vec<u8>, Option<String>)> {
        self.try_sign_op(msg, &KeyOperation::Sign, alg).await
    }

    /// Sign the provided message bytestring using `Self` and the key stored for the specified key
    /// operation.
    ///
    /// # Arguments
    ///
    /// * `msg` - The message to sign.
    /// * `op` - The key operation type.
    /// * `alg` - The algorithm to use for signing. If the signer supports multiple
    /// algorithms, this parameter is used to select the algorithm to use. If unspecified, the
    /// signer can use a default.
    ///
    /// # Returns
    ///
    /// * Signed message as a byte vector or an error if the message could not be signed.
    /// * The verification method such as a key ID or URL that can be used to look up the public
    /// key, or a serialized public key itself.
    async fn try_sign_op(
        &self,
        msg: &[u8],
        op: &KeyOperation,
        alg: Option<Algorithm>,
    ) -> Result<(Vec<u8>, Option<String>)>;

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
        data: &[u8],
        signature: &[u8],
        verification_method: Option<&str>,
    ) -> Result<()>;
}
