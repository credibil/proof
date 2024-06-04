use base64ct::{Base64UrlUnpadded, Encoding};
use did_core::error::Err;
use did_core::{tracerr, Algorithm, KeyOperation, Result, Signer};
use ecdsa::signature::Verifier;
use ecdsa::{Signature, VerifyingKey};
use reqwest::Url;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::key_bundle::JsonWebKey;
use crate::keyring::{az_to_jwk, AzureKeyRing};

/// Azure Key Vault signer.
#[allow(clippy::module_name_repetitions)]
pub struct AzureSigner {
    keyring: AzureKeyRing,
}

/// Constructor and methods for `AzureSigner`.
impl AzureSigner {
    /// Create a new `AzureSigner` instance.
    ///
    /// # Arguments
    ///
    /// * `keyring` - The keyring to use for signing.
    #[must_use]
    pub fn new(keyring: AzureKeyRing) -> Self {
        Self { keyring }
    }
}

/// Implementation of the [`Signer`] trait for Azure Key Vault.
impl Signer for AzureSigner {
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
    /// * `op` - The key operation type.
    /// * `alg` - The algorithm to use for signing. If the signer supports multiple
    /// algorithms, this parameter is used to select the algorithm to use. If unspecified, the
    /// signer can use a default.
    ///
    /// # Returns
    ///
    /// * Signed message as a byte vector or an error if the message could not be signed.
    /// * The key ID that can be used to look up the public key.
    async fn try_sign_op(
        &self, msg: &[u8], op: &KeyOperation, alg: Option<Algorithm>,
    ) -> Result<(Vec<u8>, Option<String>)> {
        let key_name = self.keyring.key_name(op);

        let algorithm = self.algorithm(alg)?;

        let hdr_bytes = serde_json::to_vec(&json!({"alg": algorithm.to_string()}))?;

        // payload as bytes
        let hdr_b64 = Base64UrlUnpadded::encode_string(&hdr_bytes);
        let msg_b64 = Base64UrlUnpadded::encode_string(msg);
        let mut payload = [hdr_b64.as_bytes(), b".", msg_b64.as_bytes()].concat();

        // hashed payload
        let digest: [u8; 32] = Sha256::digest(&payload).into();

        // sign the hashed payload
        let (az_sig, kid) = match self.keyring.client.sign(&key_name, None, &digest).await {
            Ok(s) => s,
            Err(e) => tracerr!(Err::SigningError, "Error signing data: {}", e),
        };

        // add the signature to the payload
        payload.extend(b".");
        payload.extend(az_sig);

        Ok((payload, Some(kid)))
    }

    /// Verify the provided signature against the provided message bytestring using `Self` and the
    /// key stored for the specified ID. Note that this method *does not* call the
    /// Azure Key Vault API to verify the signature. Instead, it uses the public key retrieved by
    /// looking up the key ID.
    ///
    /// # Arguments
    ///
    /// * `data` - The message to verify the signature for.
    /// * `signature` - The signature to verify.
    /// * `verification_method` - The key ID that can be used to look up the public key.
    ///
    /// # Returns
    ///
    /// An error if the signature is invalid or the message could not be verified.
    async fn verify(
        &self, data: &[u8], signature: &[u8], verification_method: Option<&str>,
    ) -> Result<()> {
        // get the public key using the URL expressed by the verification method parameter.
        let Some(vm) = verification_method else {
            tracerr!(Err::FailedSignatureVerification, "No verification method provided");
        };
        Url::parse(vm)?;
        let parts = vm.split('/').collect::<Vec<&str>>();
        if parts.len() < 2 {
            tracerr!(
                Err::InvalidInput,
                "Invalid verification method format. Need Azure Key Vault key URL"
            );
        }
        let key_name = parts[parts.len() - 2];
        let version = parts[parts.len() - 1];
        let bundle = self.keyring.client.get_key(key_name, Some(version)).await?;
        let alg = infer_algorithm(&bundle.key)?;
        let hdr_bytes = serde_json::to_vec(&json!({"alg": alg.to_string()}))?;

        // payload as bytes
        let hdr_b64 = Base64UrlUnpadded::encode_string(&hdr_bytes);
        let msg_b64 = Base64UrlUnpadded::encode_string(data);
        let payload = [hdr_b64.as_bytes(), b".", msg_b64.as_bytes()].concat();

        let key = az_to_jwk(bundle.key)?;
        let mut sec1 = vec![0x04];
        let mut x = match Base64UrlUnpadded::decode_vec(&key.x.unwrap_or_default()) {
            Ok(x) => x,
            Err(e) => tracerr!(Err::InvalidKey, "Error decoding x-value: {}", e),
        };
        sec1.append(&mut x);
        let mut y = match Base64UrlUnpadded::decode_vec(&key.y.unwrap_or_default()) {
            Ok(y) => y,
            Err(e) => tracerr!(Err::InvalidKey, "Error decoding y-value: {}", e),
        };
        sec1.append(&mut y);
        let vk = match VerifyingKey::from_sec1_bytes(&sec1) {
            Ok(vk) => vk,
            Err(e) => tracerr!(
                Err::InvalidKey,
                "Error forming verifying key from public key parts: {}",
                e
            ),
        };

        let mut decoded_signature = [0u8; 128];
        let decoded_sig = match Base64UrlUnpadded::decode(signature, &mut decoded_signature) {
            Ok(dsig) => dsig,
            Err(e) => tracerr!(Err::InvalidFormat, "Error decoding signature: {}", e),
        };
        let sig = match Signature::<k256::Secp256k1>::from_slice(decoded_sig) {
            Ok(sig) => sig,
            Err(e) => tracerr!(
                Err::FailedSignatureVerification,
                "error forming signature from slice: {}",
                e
            ),
        };

        match vk.verify(&payload, &sig) {
            Ok(()) => Ok(()),
            Err(e) => tracerr!(Err::FailedSignatureVerification, "error on verification: {}", e),
        }
    }
}

// Derive the algorithm from the key type and curve name from an Azure JSON web key format.
fn infer_algorithm(key: &JsonWebKey) -> Result<Algorithm> {
    let crv = key.curve_name.clone().unwrap_or_default();
    match (key.key_type.clone(), crv) {
        (t, c) if t == *"EC" && c == *"P-256K" => Ok(Algorithm::Secp256k1),
        (_, _) => {
            tracerr!(
                Err::InvalidKey,
                "Unable to derive a supported algorithm from the key type and curve name"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyVault;

    fn test_signer() -> AzureSigner {
        let url = std::env::var("AZURE_KEY_VAULT").expect("AZURE_KEY_VAULT env var not set");
        let namespace = format!("test-{}", uuid::Uuid::new_v4());
        let kr = AzureKeyRing::new(KeyVault::new(url.as_str()), Some(namespace));
        AzureSigner::new(kr)
    }

    #[tokio::test]
    #[ignore]
    async fn sign_then_verify() {
        let s = test_signer();

        // create a new key and activate
        let op = KeyOperation::Sign;
        let key_name = s.keyring.key_name(&op);
        let _new_key = match s.keyring.create_key(&op, true).await {
            Ok(key) => key,
            Err(e) => {
                panic!("Error creating key: {}", e);
            }
        };

        let data = b"test data";

        // sign
        let (signed_data, kid) = match s.try_sign(data, None).await {
            Ok(signed_data) => signed_data,
            Err(e) => {
                panic!("Error signing data: {}", e);
            }
        };

        // verify with public key
        let parts = signed_data.split(|b| *b == b'.').collect::<Vec<&[u8]>>();
        assert_eq!(parts.len(), 3);
        match s.verify(data, parts[2], kid.as_deref()).await {
            Ok(_) => {}
            Err(e) => panic!("Error verifying signature: {}", e),
        };

        // clean up
        s.keyring.client.delete_key(&key_name).await.expect("failed to delete key");
    }
}
