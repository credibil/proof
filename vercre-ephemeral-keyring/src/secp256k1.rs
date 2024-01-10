use k256::{PublicKey, SecretKey};
use rand_core::OsRng;
use vercre_didcore::{Jwk, Result};

use crate::{AsymmetricKey, KeyPair};

pub type Secp256k1KeyPair =
    AsymmetricKey<PublicKey, SecretKey>;

/// `KeyPair` implementation for Secp256k1.
impl KeyPair for Secp256k1KeyPair {
    /// Generate a new key pair.
    fn generate() -> Result<Self> {
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = secret_key.public_key();
        Ok(Self {
            public_key,
            secret_key: Some(secret_key),
        })
    }

    /// Express the public key as a JWK.
    fn to_jwk(&self) -> Result<Jwk> {
        let jwk = self.public_key.to_jwk_string();
        serde_json::from_str(&jwk).map_err(|e| e.into())
    }
}
