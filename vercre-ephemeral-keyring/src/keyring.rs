use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use vercre_didcore::{error::Err, Jwk, KeyOperation, KeyRing, Result};

use crate::KeyPair;

/// Ephemeral key ring.
pub struct EphemeralKeyRing<K>
where
    K: KeyPair + Send + Sync,
{
    /// Once a key is generated it can be stored for the scope of the struct.
    pub(crate) current_keys: Arc<Mutex<HashMap<KeyOperation, Arc<K>>>>,
    /// Holds newly generated keys that are not yet active.
    pub(crate) next_keys: Arc<Mutex<HashMap<KeyOperation, Arc<K>>>>,
}

/// Configuration and key generation.
impl<K> EphemeralKeyRing<K>
where
    K: KeyPair + Send + Sync,
{
    /// Create a new `EphemeralKeyRing` instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            current_keys: Arc::new(Mutex::new(HashMap::new())),
            next_keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Generate a new key pair.
    fn generate(&self) -> Result<Arc<K>> {
        let kp = K::generate()?;
        Ok(Arc::new(kp))
    }
}

/// `KeyRing` implementation
#[allow(async_fn_in_trait)]
impl<K> KeyRing for EphemeralKeyRing<K>
where
    K: KeyPair + Send + Sync,
{
    /// Get the current key for the given operation.
    async fn active_key(&self, op: &KeyOperation) -> Result<Jwk> {
        let current_keys = self.current_keys.lock().expect("lock on current_keys mutex failed");
        if current_keys.contains_key(op) {
            return current_keys[op].to_jwk();
        }
        Err(Err::KeyNotFound.into())
    }

    /// Generate a new key pair for the given operation.
    async fn next_key(&self, op: &KeyOperation) -> Result<Jwk> {
        let key = self.generate()?;
        let mut next_keys = self.next_keys.lock().expect("lock on next_keys mutex failed");
        next_keys.insert(op.clone(), key.clone());
        key.to_jwk()
    }

    /// Commit (make active) the next keys created.
    async fn commit(&self) -> Result<()> {
        let mut current_keys = self.current_keys.lock().expect("lock on current_keys mutex failed");
        let next_keys = self.next_keys.lock().expect("lock on next_keys mutex failed");
        for (op, key) in next_keys.iter() {
            current_keys.insert(op.clone(), key.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1::KeyPair as Secp256k1KeyPair;

    #[tokio::test]
    async fn test_keyring() {
        let keyring = EphemeralKeyRing::<Secp256k1KeyPair>::new();
        let first = keyring.active_key(&KeyOperation::Sign).await;
        assert!(first.is_err());
        let next = keyring.next_key(&KeyOperation::Sign).await.unwrap();
        keyring.commit().await.unwrap();
        let active = keyring.active_key(&KeyOperation::Sign).await.unwrap();
        assert_eq!(next, active);
    }
}
