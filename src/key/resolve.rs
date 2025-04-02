//! Resolution of a DID into a public key using the `did:jwk` method.

use crate::{Error, Method, MethodType, PublicKeyFormat, Resource, Url, VerificationMethod};

/// Convert a `did:key` URL into a [`VerificationMethod`] object.
/// 
/// # Errors
/// If the URL is not a valid `did:key` URL, an error is returned.
pub fn resolve(url: &Url) -> crate::Result<Resource> {
    if url.method != Method::Key {
        return Err(Error::InvalidDid(format!("DID is not a valid did:key: {url}")));
    }
    // For did:key, the fragment is the key already multibase encoded. There is
    // no need to use a builder.
    let Some(fragment) = &url.fragment else {
        return Err(Error::InvalidDid("DID is not a valid did:key - there is no fragment".into()));
    };
    let vm = VerificationMethod {
        context: None,
        id: url.resource_id(),
        type_: MethodType::Multikey,
        controller: url.did(),
        key: PublicKeyFormat::PublicKeyMultibase {
            public_key_multibase: fragment.to_string(),
        },
    };
    Ok(Resource::VerificationMethod(vm))
}
