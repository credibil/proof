//! # DID Resolver
//!
//! This crate provides a DID Resolver trait and a set of default
//! implementations for resolving DIDs.
//!
//! See [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) fpr more.

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::document::{Document, DocumentMetadata, Service, VerificationMethod};
use crate::error::Error;
use crate::{DidResolver, Method, Url, jwk, key, web, webvh};

/// Dereference a DID URL into a resource.
///
/// If you have destructured DID URL already, you can bypass this function and
/// call `deref2` directly. See [`deref2`] for more information.
///
/// # Errors
/// Will return an error if the DID URL cannot be parsed or the provided
/// resolver fails to resolve the source DID document.
///
/// Note that only URLs implying DID methods supported by this crate will
/// survive parsing.
pub async fn dereference_url(
    did_url: &str, resolver: &impl DidResolver,
) -> crate::Result<Resource> {
    let url = crate::url::Url::from_str(did_url)?;
    deref2(&url, resolver).await
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
///
/// TOOD: Rename to `derefence` when possible.
pub async fn deref2(url: &Url, resolver: &impl DidResolver) -> crate::Result<Resource> {
    match url.method {
        Method::Jwk => jwk::resolve(url),
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

/// Dereference a DID URL into a resource.
///
/// # Errors
pub async fn dereference(
    did_url: &str, opts: Option<Options>, resolver: impl DidResolver,
) -> crate::Result<Dereferenced> {
    // extract DID from DID URL
    let url = url::Url::parse(did_url)
        .map_err(|e| Error::InvalidDidUrl(format!("issue parsing URL: {e}")))?;
    let did = format!("did:{}", url.path());

    // resolve DID document
    let method = did_url.split(':').nth(1).unwrap_or_default();
    let resolution = match method {
        "key" => key::DidKey::resolve(&did)?,
        "jwk" => jwk::DidJwk::resolve(&did, opts, resolver)?,
        "web" => web::DidWeb::resolve(&did, opts, resolver).await?,
        _ => return Err(Error::MethodNotSupported(format!("{method} is not supported"))),
    };

    let Some(document) = resolution.document else {
        return Err(Error::InvalidDid("Unable to resolve DID document".into()));
    };

    // process document to dereference DID URL for requested resource
    let Some(verifcation_methods) = document.verification_method else {
        return Err(Error::NotFound("verification method missing".into()));
    };

    // for now we assume the DID URL is the ID of the verification method
    // e.g. did:web:demo.credibil.io#key-0
    let Some(vm) = verifcation_methods.iter().find(|vm| vm.id == did_url) else {
        return Err(Error::NotFound("verification method not found".into()));
    };

    Ok(Dereferenced {
        metadata: Metadata {
            content_type: ContentType::DidLdJson,
            ..Metadata::default()
        },
        content_stream: Some(Resource::VerificationMethod(vm.clone())),
        content_metadata: Some(ContentMetadata {
            document_metadata: resolution.document_metadata,
        }),
    })
}

/// Used to pass addtional values to a `resolve` and `dereference` methods. Any
/// properties used should be registered in the DID Specification Registries.
///
/// The `accept` property is common to all resolver implementations. It is used
/// by users to specify the Media Type when calling the `resolve_representation`
/// method. For example:
///
/// ```json
/// {
///    "accept": "application/did+ld+json"
/// }
/// ```
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Options {
    /// [`accept`](https://www.w3.org/TR/did-spec-registries/#accept) resolution option.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept: Option<ContentType>,
}

/// Returned by `resolve` DID methods.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Resolved {
    /// The DID resolution context.
    #[serde(rename = "@context")]
    pub context: String,

    /// Resolution metadata.
    pub metadata: Metadata,

    /// The DID document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<Document>,

    /// DID document metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_metadata: Option<DocumentMetadata>,
}

/// `Dereferenced` contains the result of dereferencing a DID URL.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Dereferenced {
    /// A metadata structure consisting of values relating to the results of the
    /// DID URL dereferencing process. MUST NOT be empty in the case of an
    /// error.
    pub metadata: Metadata,

    /// The dereferenced resource corresponding to the DID URL. MUST be empty if
    /// dereferencing was unsuccessful. MUST be empty if dereferencing is
    /// unsuccessful.
    pub content_stream: Option<Resource>,

    /// Metadata about the `content_stream`. If `content_stream` is a DID
    /// document, this MUST be `DidDocumentMetadata`. If dereferencing is
    /// unsuccessful, MUST be empty.
    pub content_metadata: Option<ContentMetadata>,
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
    //
    // /// The JSON-LD Media Type.
    // #[serde(rename = "application/ld+json")]
    // LdJson,
    /// JSON list document.
    #[serde(rename = "text/jsonl")]
    JsonL,
}

/// Metadata about the `content_stream`. If `content_stream` is a DID document,
/// this MUST be `DidDocumentMetadata`. If dereferencing is unsuccessful, MUST
/// be empty.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentMetadata {
    /// The DID document metadata.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_metadata: Option<DocumentMetadata>,
}

#[cfg(test)]
mod test {
    use anyhow::anyhow;
    use insta::assert_json_snapshot as assert_snapshot;

    use super::*;

    #[derive(Clone)]
    struct MockResolver;
    impl DidResolver for MockResolver {
        async fn resolve(&self, _url: &str) -> anyhow::Result<Document> {
            serde_json::from_slice(include_bytes!("./web/did-ecdsa.json"))
                .map_err(|e| anyhow!("issue deserializing document: {e}"))
        }
    }

    #[test]
    fn error_code() {
        let err = Error::MethodNotSupported("Method not supported".into());
        assert_eq!(err.message(), "Method not supported");
    }

    #[tokio::test]
    async fn deref_web() {
        const DID_URL: &str = "did:web:demo.credibil.io#key-0";

        let dereferenced =
            dereference(DID_URL, None, MockResolver).await.expect("should dereference");
        assert_snapshot!("deref_web", dereferenced);
    }

    #[tokio::test]
    async fn deref_key() {
        const DID_URL: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

        let dereferenced =
            dereference(DID_URL, None, MockResolver).await.expect("should dereference");
        assert_snapshot!("deref_key", dereferenced);
    }
}
