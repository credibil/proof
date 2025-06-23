//! # Status List Endpoint

use anyhow::anyhow;
use credibil_did::Document;
use credibil_did::web::create_did;
use serde::{Deserialize, Serialize};

use crate::handlers::{Body, Error, Handler, Request, Response, Result};
use crate::provider::Proof;

/// Used to query the document endpoint in order to return a DID document.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentRequest {
    /// The URL of the DID document to retrieve.
    pub url: String,
}

/// Response containing the DID document.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DocumentResponse(pub Document);

/// Document request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn document(
    _owner: &str, proof: &impl Proof, request: DocumentRequest,
) -> Result<DocumentResponse> {
    let url = request.url.trim_end_matches("/did.json").trim_end_matches("/.well-known");
    let did = create_did(url)?;

    let document =
        proof.get(&did, &did).await?.ok_or_else(|| anyhow!("document not found for did: {did}"))?;

    Ok(DocumentResponse(document))
}

impl<P: Proof> Handler<DocumentResponse, P> for Request<DocumentRequest> {
    type Error = Error;

    async fn handle(self, owner: &str, proof: &P) -> Result<impl Into<Response<DocumentResponse>>> {
        document(owner, proof, self.body).await
    }
}

impl Body for DocumentRequest {}
