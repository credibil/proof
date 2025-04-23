//! # DID Resolver
//!
//! This crate provides a DID Resolver trait and a set of default
//! implementations for resolving DIDs.
//!
//! See [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) fpr more.

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::document::{Document, Service, VerificationMethod};
use crate::error::Error;
use crate::{DidResolver, Method, Url, key, web, webvh};

/// Dereference a DID URL into a resource.
///
/// If you have destructured DID URL already, you can bypass this function and
/// call `deref_url` directly. See [`deref_url`] for more information.
///
/// # Errors
/// Will return an error if the DID URL cannot be parsed or the provided
/// resolver fails to resolve the source DID document.
///
/// Note that only URLs implying DID methods supported by this crate will
/// survive parsing.
pub async fn dereference(
    did_url: &str, resolver: &impl DidResolver,
) -> crate::Result<Resource> {
    let url = crate::url::Url::from_str(did_url)?;
    deref_url(&url, resolver).await
}

/// Dereference a structured DID URL into a resource.
///
/// Construct a structured DID URL using the `Url` struct for the `url`
/// parameter or call `dereference_url` with a string to do the same.
///
/// For DID documents that are hosted (on a web server, in a ledger, etc.), you
/// will need to implement the `DidResolver` trait for your resolver. to resolve
/// the DID document from the `Url`. This crate will then do its best to find
/// the requested resource in the document.
///
/// For self-describing DIDs a full document is never resolved. The
/// `DidResolver` can be a no-op because it's `resolve` method is not called.
/// For example, the `did:key` method can return a public key from the DID URL
/// fragment.
///
/// # Errors
/// Will return an error if the provided resolver fails to resolve the source
/// DID document.
///
/// Will also return an error if the resource is not found in the document. This
/// includes cases that don't make sense, like asking a `did:key` for a service
/// endpoint.
pub async fn deref_url(url: &Url, resolver: &impl DidResolver) -> crate::Result<Resource> {
    match url.method {
        Method::Key => key::resolve(url),
        Method::Web => {
            let doc = web::resolve(url, resolver).await?;
            document_resource(url, &doc)
        }
        Method::WebVh => {
            let doc = webvh::resolve(url, resolver).await?;
            document_resource(url, &doc)
        }
    }
}

/// Get a resource from a DID document.
///
/// Uses the `Url` to infer the type of resource to return.
///
/// # Errors
/// Will return an error if the resource is not found in the document.
pub fn document_resource(url: &Url, doc: &Document) -> crate::Result<Resource> {
    if let Some(query) = &url.query {
        if let Some(service_id) = &query.service {
            if let Some(service) = doc.get_service(service_id) {
                return Ok(Resource::Service(service.clone()));
            }
            return Err(Error::NotFound(format!("service {service_id} not found in document")));
        }
    }
    if url.fragment.is_none() {
        return Ok(Resource::Document(doc.clone()));
    }
    if let Some(vm) = doc.get_verification_method(&url.to_string()) {
        return Ok(Resource::VerificationMethod(vm.clone()));
    }
    Err(Error::NotFound(format!("verification method {url} not found in document")))
}

/// Resource represents the DID document resource returned as a result of DID
/// dereferencing. The resource is a DID document or a subset of a DID document.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Resource {
    ///  DID `Document` resource.
    Document(Document),

    /// `VerificationMethod` resource.
    VerificationMethod(VerificationMethod),

    /// `Service` resource.
    Service(Service),
}

impl Default for Resource {
    fn default() -> Self {
        Self::VerificationMethod(VerificationMethod::default())
    }
}

/// DID document metadata.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    /// The Media Type of the returned resource.
    pub content_type: ContentType,

    /// The error code from the dereferencing process, if applicable.
    /// Values of this field SHOULD be registered in the DID Specification
    /// Registries. Common values are `invalid_did_url` and `not_found`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// A human-readable explanation of the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,

    /// Additional information about the resolution or dereferencing process.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional: Option<Value>,
}

/// The Media Type of the returned resource.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum ContentType {
    /// JSON-LD representation of a DID document.
    #[default]
    #[serde(rename = "application/did+ld+json")]
    DidLdJson,
    
    /// The JSON-LD Media Type.
    #[serde(rename = "application/ld+json")]
    LdJson,

    /// JSON list document.
    #[serde(rename = "text/jsonl")]
    JsonL,
}
