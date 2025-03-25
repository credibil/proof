//! Update operation for the `did:webvh` method.
//!

use serde::{Deserialize, Serialize};

use crate::{operation::document::{DocumentBuilder, Update}, DidResolver, Document};

use super::{DidLogEntry, WitnessEntry, resolve_log};

/// Builder to update a DID document and associated log entry.
///
/// Use this to construct an [`UpdateResult`].
pub struct UpdateBuilder {
    log: Vec<DidLogEntry>,

    db: DocumentBuilder<Update>,
}

impl UpdateBuilder {
    /// Create a new `UpdateBuilder` populated with the current log entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the log entries are not valid.
    pub async fn new(
        log: Vec<DidLogEntry>, witness_proofs: Option<&[WitnessEntry]>, resolver: &impl DidResolver,
    ) -> anyhow::Result<Self> {
        // Validate the log entries by resolving the latest DID document.
        let doc = resolve_log(&log, witness_proofs, None, resolver).await?;

        // Create a new `DocumentBuilder` with the current document.
        let db = DocumentBuilder::<Update>::from(doc);

        Ok(Self { log, db })
    }
}

/// Output of an `update` operation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CreateResult {
    /// The `did:webvh` DID.
    pub did: String,

    /// The `did:webvh` document.
    pub document: Document,

    /// Version history log consisting of the original log appended with the
    /// entry describing the update operation.
    pub log: Vec<DidLogEntry>,
}
