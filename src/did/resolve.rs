//! # DID Resolver
//!
//! This crate provides a DID Resolver trait and a set of default
//! implementations for resolving DIDs.
//!
//! See [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) fpr more.

use std::str::FromStr;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::IdentityResolver;
use crate::did::url::Url;
use crate::did::{Document, Method, Service, VerificationMethod, key, web, webvh};

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
pub async fn dereference(did_url: &str, resolver: &impl IdentityResolver) -> Result<Resource> {
    let url = Url::from_str(did_url)?;
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
pub async fn deref_url(url: &Url, resolver: &impl IdentityResolver) -> Result<Resource> {
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
pub fn document_resource(url: &Url, doc: &Document) -> Result<Resource> {
    if let Some(query) = &url.query {
        if let Some(service_id) = &query.service {
            if let Some(service) = doc.service(service_id) {
                return Ok(Resource::Service(service.clone()));
            }
            bail!("service {service_id} not found in document");
        }
    }
    if url.fragment.is_none() {
        return Ok(Resource::Document(doc.clone()));
    }
    if let Some(vm) = doc.verification_method(&url.to_string()) {
        return Ok(Resource::VerificationMethod(vm.clone()));
    }
    bail!("verification method {url} not found in document")
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
