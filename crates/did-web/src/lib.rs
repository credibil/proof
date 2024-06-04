//! # DID Web Implementation
//! <https://w3c-ccg.github.io/did-method-web/>

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

/// DID Web registrar. Implementation of the applicable DID operations, other than Read.
pub mod registrar;

/// DID Web resolver. Implementation of the DID Read operation.
pub mod resolver;

use did_core::{KeyRing, Signer};

/// Registrar that implements the DID Web method.
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