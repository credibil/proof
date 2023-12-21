use vercre_didcore::{KeyRing, Signer};

/// Registrar that implements the Web DID method.
pub struct Registrar<K>
where
    K: KeyRing + Signer,
{
    /// Domain at which the DID resolution can be reached. For example "example.com". In this case
    /// it is assumed a public DID document (one in which a path is not specified) would be
    /// available at https://example.com/.well-known/did.json.
    pub domain: String,
    /// Key ring for managing keys and signing.
    pub(crate) keyring: K,
    /// Controller of the verification methods.
    pub(crate) controller: Option<String>,
}

/// Configuration and internals.
impl<K> Registrar<K>
where
    K: KeyRing + Signer,
{
    /// Create a new registrar.
    pub fn new(domain: &str, keyring: K, controller: Option<String>) -> Self {
        Self {
            domain: domain.to_string(),
            keyring,
            controller,
        }
    }
}
