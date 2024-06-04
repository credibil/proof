//! # DID JWK Implementation
//! <https://github.com/quartzjer/did-jwk/blob/main/spec.md>

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

/// DID JWK registrar. Implementation of the applicable DID operations, other than Read.
pub mod registrar;
/// DID JWK resolver. Implementation of the DID Read operation.
pub mod resolver;

use did_core::{
    Action, Context, DidDocument, Jwk, KeyPurpose, Patch, Result, VerificationMethod,
    VmWithPurpose, DID_CONTEXT,
};
use keyring::{EphemeralKeyRing, KeyPair};

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
    #[must_use]
    pub fn new(keyring: &'a EphemeralKeyRing<K>) -> Self {
        Self { keyring }
    }
}

// Convert a JWK to a DID document.
pub(crate) fn document_from_jwk(key: &Jwk, type_: &str, did: &str) -> Result<DidDocument> {
    let mut doc = DidDocument {
        context: vec![Context {
            url: Some(DID_CONTEXT.to_string()),
            ..Default::default()
        }],
        id: did.to_string(),
        ..Default::default()
    };

    let mut vm = VmWithPurpose {
        verification_method: VerificationMethod {
            id: format!("{did}#0"),
            controller: did.to_string(),
            type_: type_.to_string(),
            public_key_jwk: Some(key.clone()),
            ..Default::default()
        },
        purposes: Some(vec![
            KeyPurpose::Authentication,
            KeyPurpose::AssertionMethod,
            KeyPurpose::CapabilityDelegation,
            KeyPurpose::CapabilityInvocation,
        ]),
    };
    if key.use_ != Some("sig".to_string()) {
        if let Some(purposes) = vm.purposes.as_mut() {
            purposes.push(KeyPurpose::KeyAgreement);
        } else {
            vm.purposes = Some(vec![KeyPurpose::KeyAgreement]);
        }
    }
    let patch_key = Patch::builder(Action::AddPublicKeys).public_key(&vm)?.build()?;
    doc.apply_patches(&[patch_key]);
    Ok(doc)
}
