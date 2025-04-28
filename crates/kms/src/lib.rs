//! Key management

use std::collections::HashMap;

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_identity::{did, Key, SignerExt};
use credibil_jose::{Algorithm, PublicKeyJwk, Signer};
use ed25519_dalek::{Signer as _, SigningKey};
use rand::rngs::OsRng;

#[derive(Clone, Debug)]
pub struct Keyring {
    keys: HashMap<String, String>,
    next_keys: HashMap<String, String>,
}

impl Keyring {
    // Create a new keyring and add a signing key.
    #[must_use]
    pub fn new() -> Self {
        let mut kr = Self {
            keys: HashMap::new(),
            next_keys: HashMap::new(),
        };
        kr.add_key("signing").expect("should add signing key");
        kr
    }

    // Add a newly generated key to the keyring and corresponding next key.
    pub fn add_key(&mut self, id: impl ToString) -> anyhow::Result<()> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let key = Base64UrlUnpadded::encode_string(signing_key.as_bytes());
        self.keys.insert(id.to_string(), key);

        let next_signing_key = SigningKey::generate(&mut OsRng);
        let next_key = Base64UrlUnpadded::encode_string(next_signing_key.as_bytes());
        self.next_keys.insert(id.to_string(), next_key);

        Ok(())
    }

    // Replace a key in the keyring with a new one.
    pub fn replace(&mut self, id: impl ToString) -> anyhow::Result<PublicKeyJwk> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key().as_bytes().to_vec();
        let key = Base64UrlUnpadded::encode_string(signing_key.as_bytes());
        self.keys.insert(id.to_string(), key);

        let next_signing_key = SigningKey::generate(&mut OsRng);
        let next_key = Base64UrlUnpadded::encode_string(next_signing_key.as_bytes());
        self.next_keys.insert(id.to_string(), next_key);

        Ok(PublicKeyJwk::from_bytes(&verifying_key)?)
    }

    // Rotate keys
    pub fn rotate(&mut self) -> anyhow::Result<()> {
        for (id, next_key) in self.next_keys.iter() {
            *self.keys.entry(id.clone()).or_insert(next_key.clone()) = next_key.clone();
        }
        self.next_keys.clear();
        for id in self.keys.keys() {
            let signing_key = SigningKey::generate(&mut OsRng);
            let key = Base64UrlUnpadded::encode_string(signing_key.as_bytes());
            self.next_keys.insert(id.clone(), key);
        }
        Ok(())
    }

    // Get a public JWK for a key in the keyring.
    //
    // This will always return a result if it can. If the key is not found, one
    // will be generated with the specified ID.
    pub fn jwk(&mut self, id: impl ToString + Clone) -> anyhow::Result<PublicKeyJwk> {
        let secret = match self.keys.get(&id.to_string()) {
            Some(secret) => secret,
            None => {
                self.add_key(id.clone())?;
                self.keys
                    .get(&id.to_string())
                    .ok_or_else(|| anyhow!("key not found after generating new key"))?
            }
        };
        let key_bytes = Base64UrlUnpadded::decode_vec(&secret)?;
        let secret_key: ed25519_dalek::SecretKey =
            key_bytes.try_into().map_err(|_| anyhow::anyhow!("invalid secret key"))?;
        let signing_key = SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key().as_bytes().to_vec();
        Ok(PublicKeyJwk::from_bytes(&verifying_key)?)
    }

    // Get a public multibase key for a key in the keyring.
    pub fn multibase(&mut self, id: impl ToString + Clone) -> anyhow::Result<String> {
        let key = self.jwk(id)?;
        Ok(key.to_multibase()?)
    }

    // Get a public JWK for a next key in the keyring.
    //
    // This will fail with an error if the key is not found or any encoding
    // errors occur.
    pub fn next_jwk(&self, id: impl ToString + Clone) -> anyhow::Result<PublicKeyJwk> {
        if let Some(secret) = self.next_keys.get(&id.to_string()).cloned() {
            let key_bytes = Base64UrlUnpadded::decode_vec(&secret)?;
            let secret_key: ed25519_dalek::SecretKey =
                key_bytes.try_into().map_err(|_| anyhow::anyhow!("invalid secret key"))?;
            let signing_key = SigningKey::from_bytes(&secret_key);
            let verifying_key = signing_key.verifying_key().as_bytes().to_vec();
            return Ok(PublicKeyJwk::from_bytes(&verifying_key)?);
        }
        Err(anyhow!("key not found"))
    }

    // Get a public multibase key for a next key in the keyring.
    //
    // Will fail with an error if the key is not found or any encoding errors
    // occur.
    pub fn next_multibase(&self, id: impl ToString + Clone) -> anyhow::Result<String> {
        let key = self.next_jwk(id)?;
        Ok(key.to_multibase()?)
    }
}

impl Signer for Keyring {
    async fn try_sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        if let Some(secret) = self.keys.get("signing").cloned() {
            let key_bytes = Base64UrlUnpadded::decode_vec(&secret)?;
            let secret_key: ed25519_dalek::SecretKey =
                key_bytes.try_into().map_err(|_| anyhow::anyhow!("invalid secret key"))?;
            let signing_key = SigningKey::from_bytes(&secret_key);
            return Ok(signing_key.sign(msg).to_bytes().to_vec());
        }
        Err(anyhow!("key not found"))
    }

    async fn verifying_key(&self) -> anyhow::Result<Vec<u8>> {
        if let Some(secret) = self.keys.get("signing").cloned() {
            let key_bytes = Base64UrlUnpadded::decode_vec(&secret)?;
            let secret_key: ed25519_dalek::SecretKey =
                key_bytes.try_into().map_err(|_| anyhow::anyhow!("invalid secret key"))?;
            let signing_key = SigningKey::from_bytes(&secret_key);
            let verifying_key = signing_key.verifying_key().as_bytes().to_vec();
            return Ok(verifying_key);
        }
        Err(anyhow!("key not found"))
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

impl SignerExt for Keyring {
    async fn verification_method(&self) -> anyhow::Result<Key> {
        let Some(secret) = self.keys.get("signing") else {
            return Err(anyhow!("signing key for verification method not found"));
        };
        let key_bytes = Base64UrlUnpadded::decode_vec(&secret)?;
        let secret_key: ed25519_dalek::SecretKey =
            key_bytes.try_into().map_err(|_| anyhow::anyhow!("invalid secret key"))?;
        let signing_key = SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key().as_bytes().to_vec();
        let jwk = PublicKeyJwk::from_bytes(&verifying_key)?;
        let vm = did::key::did_from_jwk(&jwk)?;
        Ok(Key::KeyId(vm))
    }
}
