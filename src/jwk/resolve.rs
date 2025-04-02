//! Resolution of a DID into a public key using the `did:jwk` method.

use base64ct::{Base64UrlUnpadded, Encoding};

use crate::{Error, Method, MethodType, Resource, Url, VerificationMethodBuilder, VmKeyId};

/// Convert a `did:jwk` URL into a [`VerificationMethod`] object.
/// 
/// # Errors
/// If the URL is not a valid `did:jwk` URL, an error is returned. 
pub fn resolve(url: &Url) -> crate::Result<Resource> {
    if url.method != Method::Jwk {
        return Err(Error::InvalidDid(format!("DID is not a valid did:jwk: {url}")));
    }
    // For JWK, the method-specific identifier is the encoded key.
    let decoded = Base64UrlUnpadded::decode_vec(&url.id)
        .map_err(|e| Error::InvalidDid(format!("issue decoding key: {e}")))?;
    let jwk = serde_json::from_slice(&decoded)
        .map_err(|e| Error::InvalidDid(format!("issue deserializing key: {e}")))?;

    let vm = VerificationMethodBuilder::new(&jwk)
        .key_id(&url.resource_id(), VmKeyId::Index(String::new(), 0))?
        .method_type(&MethodType::JsonWebKey2020)?
        .build();
    
    Ok(Resource::VerificationMethod(vm))
}