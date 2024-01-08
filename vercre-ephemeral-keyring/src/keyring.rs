use std::{collections::HashMap, sync::{Arc, Mutex}};

use vercre_didcore::{Algorithm, KeyRing, Result, Jwk, KeyOperation, error::Err};

/// Ephemeral key ring.
pub struct EphemeralKeyRing {
    // Configure the key type to use by using the constructor.
    key_type: Algorithm,
    // Once a key is generated it can be stored for the scope of the struct.
    current_keys: Arc<Mutex<HashMap<KeyOperation, Jwk>>>,
    // Holds newly generated keys that are not yet active.
    next_keys: Arc<Mutex<HashMap<KeyOperation, Jwk>>>,
}

/// Configuration and key generation.
impl EphemeralKeyRing {
    /// Create a new `EphemeralKeyRing` instance.
    #[must_use]
    pub fn new(key_type: Algorithm) -> Self {
        Self {
            key_type,
            current_keys: Arc::new(Mutex::new(HashMap::new())),
            next_keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Generate a new key pair for the configured key type.
    pub fn generate(&self) -> Result<Jwk> {
        Err(Err::KeyNotFound.into())
        // match self.key_type {
        //     KeyPair::Ed25519 => {
        //         let (pk, sk) = ed25519_dalek::Keypair::generate(&mut rand::thread_rng()).to_bytes();
        //         Ok(Jwk {
        //             kty: "OKP".to_string(),
        //             crv: Some("Ed25519".to_string()),
        //             x: Some(base64::encode_config(&pk, base64::URL_SAFE_NO_PAD)),
        //             d: Some(base64::encode_config(&sk, base64::URL_SAFE_NO_PAD)),
        //             ..Default::default()
        //         })
        //     }
        //     KeyPair::Secp256k1 => {
        //         let sk = secp256k1::SecretKey::random(&mut rand::thread_rng());
        //         let pk = secp256k1::PublicKey::from_secret_key(&sk);
        //         Ok(Jwk {
        //             kty: "EC".to_string(),
        //             crv: Some("secp256k1".to_string()),
        //             x: Some(base64::encode_config(&pk.serialize_uncompressed()[1..33], base64::URL_SAFE_NO_PAD)),
        //             y: Some(base64::encode_config(&pk.serialize_uncompressed()[33..65], base64::URL_SAFE_NO_PAD)),
        //             d: Some(base64::encode_config(&sk.serialize(), base64::URL_SAFE_NO_PAD)),
        //             ..Default::default()
        //         })
        //     }
        // }
    }
}

/// `KeyRing` implementation
#[allow(async_fn_in_trait)]
impl KeyRing for EphemeralKeyRing {
    /// Get the current key for the given operation.
    async fn active_key(&self, op: &KeyOperation) -> Result<Jwk> {
        let current_keys = {
            let ck = self.current_keys.lock().expect("lock on current_keys mutex failed");
            ck.clone()
        };
        if current_keys.contains_key(op) {
            return Ok(current_keys[op].clone());
        }
        Err(Err::KeyNotFound.into())
    }

    /// Generate a new key pair for the given operation.
    async fn next_key(&self, op: &KeyOperation) -> Result<Jwk> {
        let key = self.generate()?;
        let mut next_keys = {
            let nk = self.next_keys.lock().expect("lock on next_keys mutex failed");
            nk.clone()
        };
        next_keys.insert(op.clone(), key.clone());
        Ok(key)
    }

    /// Commit (make active) the next keys created.
    async fn commit(&self) -> Result<()> {
        let mut current_keys = {
            let ck = self.current_keys.lock().expect("lock on current_keys mutex failed");
            ck.clone()
        };
        let mut next_keys = {
            let nk = self.next_keys.lock().expect("lock on next_keys mutex failed");
            nk.clone()
        };
        for (op, key) in next_keys.iter() {
            current_keys.insert(op.clone(), key.clone());
        }
        next_keys.clear();
        Ok(())
    }
}
