use base64ct::{Base64UrlUnpadded, Encoding};
use ecdsa::signature::{Signer, Verifier};
use ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::{PublicKey, Secp256k1};
use rand::rngs::OsRng;
use serde_json::json;
use sha2::{Digest, Sha256};
use did_core::error::Err;
use did_core::{tracerr, Algorithm, Jwk, Result};

use crate::{AsymmetricKey, KeyPair as KeyPairBehavior};

/// Key pair for Secp256k1.
pub type KeyPair = AsymmetricKey<VerifyingKey<Secp256k1>, SigningKey<Secp256k1>>;

/// `KeyPair` implementation for Secp256k1.
impl KeyPairBehavior for KeyPair {
    /// The algorithm used to generate a key pair.
    fn key_type() -> Algorithm {
        Algorithm::Secp256k1
    }

    /// Generate a new key pair.
    fn generate() -> Result<Self> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            verifying_key: *verifying_key,
            signing_key: Some(signing_key),
        })
    }

    /// Express the public key as a JWK.
    fn to_jwk(&self) -> Result<Jwk> {
        let public_key = PublicKey::from(self.verifying_key);
        let jwk = public_key.to_jwk_string();
        serde_json::from_str(&jwk).map_err(std::convert::Into::into)
    }

    /// Sign a message.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let hdr_b = match serde_json::to_vec(&json!({"alg": Self::key_type().to_string()})) {
            Ok(b) => b,
            Err(e) => {
                tracerr!(Err::SerializationError, "failed to serialize header: {}", e);
            }
        };
        let hdr_64 = Base64UrlUnpadded::encode_string(&hdr_b);
        let msg_64 = Base64UrlUnpadded::encode_string(msg);
        let mut payload = [hdr_64.as_bytes(), b".", msg_64.as_bytes()].concat();
        let digest: [u8; 32] = Sha256::digest(&payload).into();

        let Some(sk) = &self.signing_key else {
            tracerr!(Err::InvalidConfig, "no secret key");
        };
        let sig: Signature<Secp256k1> = sk.sign(&digest);
        let encoded_sig = Base64UrlUnpadded::encode_string(&sig.to_bytes());

        payload.extend(b".");
        payload.extend(encoded_sig.as_bytes());
        Ok(payload)
    }

    /// Verify a signature.
    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        let hdr_b = serde_json::to_vec(&json!({"alg": Self::key_type().to_string()}))
            .expect("failed to serialize");
        let hdr_64 = Base64UrlUnpadded::encode_string(&hdr_b);
        let msg_64 = Base64UrlUnpadded::encode_string(msg);
        let payload = [hdr_64.as_bytes(), b".", msg_64.as_bytes()].concat();
        let digest: [u8; 32] = Sha256::digest(payload).into();

        let mut decoded_signature = [0u8; 128];
        let decoded_sig = Base64UrlUnpadded::decode(sig, &mut decoded_signature)?;
        let sig = Signature::<Secp256k1>::from_slice(decoded_sig)?;

        match self.verifying_key.verify(&digest, &sig) {
            Ok(()) => Ok(()),
            Err(e) => {
                tracerr!(Err::FailedSignatureVerification, "Error verifying signature: {}", e)
            }
        }
    }
}
