use anyhow::Result;

use crate::did::web::default_did;
use crate::did::{Document, DocumentBuilder};

/// Builder to create a new `did:webvh` document and associated DID url and log.
///
/// Use this to construct a `CreateResult`.
pub struct CreateBuilder<D> {
    url: String,
    document: D,
}

/// Builder does not have a document (can't build).
pub struct NoDocument;

/// Builder has a document (can build).
pub struct WithDocument(DocumentBuilder);

impl CreateBuilder<NoDocument> {
    /// Create a new `CreateBuilder`.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            document: NoDocument,
        }
    }

    /// Add a populated [`DocumentBuilder`] instance.
    #[must_use]
    pub fn document(self, builder: DocumentBuilder) -> CreateBuilder<WithDocument> {
        CreateBuilder {
            url: self.url,
            document: WithDocument(builder),
        }
    }
}

impl CreateBuilder<WithDocument> {
    /// Build the `CreateResult` with the provided parameters.
    ///
    /// This will return an error if the document is not valid or if the
    /// parameters are not set correctly.
    ///
    /// # Errors
    ///
    /// Returns an error if the DID URL is invalid or if the document cannot
    /// be built.
    pub fn build(self) -> Result<Document> {
        let did = default_did(&self.url)?;
        self.document.0.build(did)
    }
}
