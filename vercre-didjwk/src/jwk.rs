use vercre_ephemeral_keyring::{EphemeralKeyRing, KeyPair};

/// Registrar that implements the DID JWK method.
pub struct Registrar<K>
where
    K: KeyPair + Send + Sync,
{
    /// Key ring for managing keys and signing.
    pub(crate) keyring: EphemeralKeyRing<K>,
}

/// Configuration and internals.
impl<K> Registrar<K>
where
    K: KeyPair + Send + Sync,
{
    /// Create a new registrar.
    /// 
    /// # Arguments
    /// 
    /// * `keyring` - The keyring to use for generating a signing/verification key pair.
    /// 
    /// # Returns
    /// 
    /// * The registrar with the keyring configured.
    pub fn new(keyring: EphemeralKeyRing<K>) -> Self {
        Self { keyring }
    }
}
