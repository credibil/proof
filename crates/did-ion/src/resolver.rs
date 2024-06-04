//! # ION DID Resolver

use did_core::{KeyRing, Resolution, Resolver, Result, Signer};

use crate::Registrar;

/// A Resolver is responsible for resolving a DID to a DID document. This implementation will make
/// a resolution request to the ION registrar. If the DID has been anchored, a lookup is done to
/// retrieve the latest version of the DID document using the short-form DID as the URL. If the DID
/// has just been created or replaced and is not yet anchored, passing in a long-form DID will
/// unpack that into a full DID document, otherwise if a short DID is passed in the resolver will
/// fail.
///
/// # Arguments
///
/// * `did` - The DID to resolve. Short-form or long-form.
///
/// # Returns
///
/// The DID document with the ID corresponding to the supplied DID.
impl<K> Resolver for Registrar<K>
where
    K: KeyRing + Signer + Send + Sync,
{
    async fn resolve(&self, did: &str) -> Result<Resolution> {
        self.resolve_did(did).await
    }
}
