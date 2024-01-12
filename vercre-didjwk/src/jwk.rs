use vercre_ephemeral_keyring::{EphemeralKeyRing, KeyPair};

/// Registrar that implements the DID JWK method.
pub struct Registrar<'a, K>
where
    K: KeyPair + Send + Sync,
{
    /// Key ring for managing keys and signing.
    pub(crate) keyring: &'a EphemeralKeyRing<K>,
}

/// Configuration and internals.
impl<'a, K> Registrar<'a, K>
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
    pub fn new(keyring: &'a EphemeralKeyRing<K>) -> Self {
        Self { keyring }
    }
}
