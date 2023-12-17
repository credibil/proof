use vercre_didcore::{DidDocument, KeyRing, Resolution, Resolver, Result, Signer, DID_CONTEXT, DocumentMetadata, ResolutionMetadata};
use reqwest::Url;

use crate::web::WebRegistrar;

/// A Resolver is responsible for resolving a DID to a DID document. This implementation will make
/// a resolution request to an http end point to retrieve a DID document.
///
/// # Arguments
///
/// * `did` - The DID to resolve. Must be of the form did:web:domain[%3A][port][path]. Port is
/// optional and must be preceded by a url-encoded colon (%3A). Path is optional and sub-paths
/// should be separated by colons.
///
///
/// # Returns
///
/// The DID document with the ID corresponding to the supplied DID.
#[allow(async_fn_in_trait)]
impl<K> Resolver for WebRegistrar<K>
where
    K: KeyRing + Signer + Send + Sync,
{
    async fn resolve(&self, did: &str) -> Result<Resolution> {
        let mut content_type = "application/did+json".to_string();

        if !did.starts_with("did:web:") {
            return Ok(error_response("invalidDid"));
        }

        let has_path = did.matches(":").count() > 2;
        let mut path = "https://".to_owned()
            + &did.trim_start_matches("did:web:").to_string().replace(":", "/").replace("%3A", ":");
        if has_path {
            path = path + "/did.json";
        } else {
            path = path + "/.well-known/did.json";
        } 
        let url = match Url::parse(&path) {
            Ok(u) => u,
            Err(_) => {
                return Ok(error_response("invalidDid"));
            }
        };

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        let http_client = reqwest::Client::builder()
            .default_headers(headers)
            .build()?;
        let res = match http_client.get(url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("Error sending DID resolution request: {}", e);
                return Ok(error_response("internalError"));
            }
        };

        if !res.status().is_success() {
            tracing::trace!("Error return from DID resolution request: {}", res.status());
            return Ok(error_response("notFound"));
        }

        let doc = res.json::<DidDocument>().await?;
        if !doc.context.is_empty() {
            content_type = "application/did+ld+json".to_string();
        }

        Ok(Resolution {
            context: DID_CONTEXT.to_string(),
            did_document: Some(doc),
            did_document_metadata: Some(DocumentMetadata::default()),
            did_resolution_metadata: Some(ResolutionMetadata {
                content_type,
                error: None,
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
            content_type: "application/did+json".to_string(),
            error: Some(error.to_string()),
        }),
    }
}