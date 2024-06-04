use base64ct::{Base64UrlUnpadded, Encoding};
use did_core::{
    DocumentMetadata, Jwk, Resolution, ResolutionMetadata, Resolver, Result, DID_CONTEXT,
};
use keyring::KeyPair;

use crate::{document_from_jwk, Registrar};

/// Resolver implementation for the JWK method.
///
/// # Arguments
///
/// * `did` - The DID to resolve.
///
/// # Returns
///
/// The DID document with a single verification method corresponding to the supplied DID and the
/// corresponding verification method references for the possible purposes implied by the JWK
/// encoded in the DID.
impl<'a, K> Resolver for Registrar<'a, K>
where
    K: KeyPair + Send + Sync,
{
    async fn resolve(&self, did: &str) -> Result<Resolution> {
        if !did.starts_with("did:jwk:") {
            return Ok(error_response("invalidDid"));
        }
        let content_type = "application/did+ld+json".to_string();

        let parts = did.split(':').collect::<Vec<&str>>();
        if parts.len() != 3 {
            return Ok(error_response("invalidDid"));
        }

        let encoded = parts[2];
        let serialized = Base64UrlUnpadded::decode_vec(encoded)?;
        let key: Jwk = serde_json::from_slice(&serialized)?;

        let doc = document_from_jwk(&key, &K::key_type().cryptosuite(), did);
        Ok(Resolution {
            context: DID_CONTEXT.to_string(),
            did_document: Some(doc?),
            did_document_metadata: Some(DocumentMetadata::default()),
            did_resolution_metadata: Some(ResolutionMetadata {
                content_type,
                ..Default::default()
            }),
        })
    }
}

fn error_response(error: &str) -> Resolution {
    Resolution {
        context: DID_CONTEXT.to_string(),
        did_document: None,
        did_document_metadata: Some(DocumentMetadata::default()),
        did_resolution_metadata: Some(ResolutionMetadata {
            content_type: "application/did+ld+json".to_string(),
            error: Some(error.to_string()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use did_core::DID_CONTEXT;
    use keyring::{EphemeralKeyRing, Secp256k1KeyPair};

    use super::*;
    use crate::Registrar;

    #[tokio::test]
    async fn test_resolve_invalid_did_method() {
        let keyring = EphemeralKeyRing::<Secp256k1KeyPair>::new();
        let registrar = Registrar::new(&keyring);
        let resolution = registrar.resolve("did:web:wibble").await.unwrap();
        assert_eq!(resolution.context, DID_CONTEXT);
        assert!(resolution.did_document.is_none());
        assert!(resolution.did_document_metadata.is_some());
        assert!(resolution.did_resolution_metadata.is_some());
        let md = resolution.did_resolution_metadata.unwrap();
        assert_eq!(md.clone().content_type, "application/did+ld+json");
        assert_eq!(md.clone().error.unwrap(), "invalidDid");
    }

    #[tokio::test]
    async fn test_resolve_secp256k1_did() {
        let did = "did:jwk:eyJrdHkiOiJFQyIsImNydiI6InNlY3AyNTZrMSIsIngiOiJKSnpQaTRxeTJydktTVk85RjItMDVWV2VYMm9oc3dYN1NUbzg3TUdxcVB3IiwieSI6IkMxUnRGbnFXOWxOTEI1ejcycG9uMTIzZHh2MWtEcVUzUWw1QjhzMFdjXzQifQ".to_string();
        let keyring = EphemeralKeyRing::<Secp256k1KeyPair>::new();
        let registrar = Registrar::new(&keyring);
        let resolution = registrar.resolve(&did).await.unwrap();
        insta::with_settings!( {sort_maps => true}, {
            insta::assert_yaml_snapshot!(resolution);
        });
    }
}
