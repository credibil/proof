//! Definition for a DID document resolver.

use serde::{Deserialize, Serialize};

use crate::{
    document::{
        verification_method::{KeyPurpose, VerificationMethod},
        DidDocument,
    },
    error::Err,
    tracerr,
    Result,
};

/// Metadata associated with a DID resolution response.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionMetadata {
    /// The content type of the response. e.g. "application/did+ld+json".
    pub content_type: String,
    /// An error code if the resolution failed. See https://www.w3.org/TR/did-spec-registries/#error
    /// for a list of valid strings.
    pub error: Option<String>,
}

/// Metadata associated with a DID document.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentMetadata {
    /// The time the document was created. The value of the property is a string formatted as an XML
    /// Datetime normalized to UTC 00:00:00 and without sub-second decimal precision. For example:
    /// 2020-12-20T19:17:47Z.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// The time the document was last updated. The value of the property must follow the same
    /// formatting rules as the created property. The updated property is omitted if an Update
    /// operation has never been performed on the DID document. If an updated property exists, it
    /// can be the same value as the created property when the difference between the two timestamps
    /// is less than one second.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    /// If a DID has been deactivated, DID document metadata must include this property with the
    /// boolean value true. If a DID has not been deactivated, this property is optional, but if
    /// included, must have the boolean value false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,
    /// DID document metadata may include a nextUpdate property if the resolved document version is
    /// not the latest version of the document. It indicates the timestamp of the next Update
    /// operation. The value of the property must follow the same formatting rules as the created
    /// property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_update: Option<String>,
    /// DID document metadata should include a versionId property to indicate the version of the
    /// last Update operation for the document version which was resolved. The value of the property
    /// must be an ASCII string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    /// DID document metadata may include a nextVersionId property if the resolved document version
    /// is not the latest version of the document. It indicates the version of the next Update
    /// operation. The value of the property must be an ASCII string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_version_id: Option<String>,
    /// A DID method can define different forms of a DID that are logically equivalent.
    /// An example is when a DID takes one form prior to registration in a verifiable data registry
    /// and another form after such registration. In this case, the DID method specification might
    /// need to express one or more DIDs that are logically equivalent to the resolved DID as a
    /// property of the DID document. This is the purpose of the equivalentId property.
    /// If present, the equivalentId value must be a set where each item is a string that conforms
    /// to a DID URL Syntax.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub equivalent_id: Option<Vec<String>>,
    /// The canonicalId property is identical to the equivalentId property except:
    ///
    /// 1. it is associated with a single value rather than a set, and
    /// 2. the DID is defined to be the canonical ID for the DID subject within the scope of the
    /// containing DID document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_id: Option<String>,
}

/// Return type from a DID document resolution.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Resolution {
    /// The context of the DID document. e.g. "https://w3id.org/did-resolution/v1"
    #[serde(rename = "@context")]
    pub context: String,
    /// The DID document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document: Option<DidDocument>,
    /// Metadata associated with the document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_metadata: Option<DocumentMetadata>,
    /// Metadata associated with the response to the resolution request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_resolution_metadata: Option<ResolutionMetadata>,
}

/// A Resolver is responsible for resolving a DID to a DID document representation.
#[allow(async_fn_in_trait)]
pub trait Resolver {
    /// Resolve a DID to a DID document.
    ///
    /// # Arguments
    ///
    /// * `did` - The DID to resolve.
    ///
    /// # Returns
    ///
    /// The DID document and associated metadata. If the resolution fails, it should return an
    /// Error::NotFound.
    async fn resolve(&self, did: &str) -> Result<Resolution>;

    /// Convenience method that resolves a DID to a DID document and then extracts a public key
    /// from it. This default finds the first public key that matches the required purpose.
    ///
    /// # Arguments
    ///
    /// * `did` - The DID to resolve.
    /// * `purpose` - The purpose of the key to extract.
    ///
    /// # Returns
    ///
    /// The public key matching the criteria. If no key is found, returns an error.
    async fn resolve_key(&self, did: &str, purpose: KeyPurpose) -> Result<VerificationMethod> {
        let res = self.resolve(did).await?;
        match res.did_document {
            None => tracerr!(Err::NotFound, "DID not found"),
            Some(doc) => {
                doc.get_key(purpose)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, path::PathBuf};

    use super::*;

    #[test]
    fn deserialize_resolution() {
        let mut r = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        r.push("test_data/resolved_doc.json");
        let file = File::open(r.as_path()).unwrap();
        let res: Resolution = serde_json::from_reader(file).unwrap();
        insta::assert_yaml_snapshot!(res);
    }
}
