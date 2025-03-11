//! Create operation for the `did:webvh` method.
//!

use anyhow::bail;
use serde::{Deserialize, Serialize};

use crate::{core::Kind, document::{Service, VerificationMethod}, Document, DocumentBuilder, KeyPurpose};

use super::{BASE_CONTEXT, DidLogEntry, METHOD, Parameters, SCID_PLACEHOLDER, VERSION, Witness};

/// Output of a `create` operation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CreateResult {
    /// The `did:webvh` id (url).
    pub did: String,

    /// The `did:webvh` document.
    pub document: Document,

    /// Version history log file.
    pub log: Vec<DidLogEntry>,
}

/// Builder of a `did:webvh` document and associated log entries.
///
/// This builder is the implementation of the DID method's `create` operation.
pub struct CreateBuilder {
    // Parameters under construction
    params: Parameters,

    // Document under construction
    doc_builder: DocumentBuilder,
}

impl CreateBuilder {
    /// Start a new `create` operation.
    ///
    /// # Errors
    ///
    /// Will fail if no update keys are provided.
    pub fn new(domain: &str, update_keys: &[&str]) -> anyhow::Result<Self> {
        if update_keys.is_empty() {
            bail!("At least one update key is required for the create operation.");
        }

        let params = Parameters {
            method: format!("did:{METHOD}:{VERSION}"),
            update_keys: update_keys.iter().map(std::string::ToString::to_string).collect(),
            ..Default::default()
        };

        let controller = format!("did:{METHOD}:{SCID_PLACEHOLDER}:{domain}");
        let mut doc = DocumentBuilder::new(&controller);
        for c in &BASE_CONTEXT {
            doc = doc.context(&Kind::String((*c).to_string()));
        }
        doc = doc.controller(&controller);

        Ok(Self {
            params,
            doc_builder: doc,
        })
    }

    /// Add a verification relationship (key) to the document.
    ///
    /// Chain to add multiple verification relationships.
    ///
    /// # Errors
    ///
    /// Will fail if the verification relationship is invalid.
    pub fn verification_relationship(
        mut self, relationship: &KeyPurpose, vm: &Kind<VerificationMethod>,
    ) -> anyhow::Result<Self> {
        self.doc_builder = self.doc_builder.verification_relationship(relationship, vm)?;
        Ok(self)
    }

    /// Add an also known as (AKA) to the document.
    #[must_use]
    pub fn also_known_as(mut self, aka: &str) -> Self {
        self.doc_builder = self.doc_builder.also_known_as(aka);
        self
    }

    /// Add another controller to the document besides the default.
    #[must_use]
    pub fn controller(mut self, controller: &str) -> Self {
        self.doc_builder = self.doc_builder.controller(controller);
        self
    }

    /// Add a service endpoint to the document.
    #[must_use]
    pub fn service(mut self, service: &Service) -> Self {
        self.doc_builder = self.doc_builder.service(service);
        self
    }

    /// Add another context in addition to the base ones for this DID method.
    #[must_use]
    pub fn context(mut self, context: &Kind<serde_json::Value>) -> Self {
        self.doc_builder = self.doc_builder.context(context);
        self
    }

    /// Add a set of witnesses to the create operation.
    ///
    /// # Errors
    ///
    /// Will fail if the witness threshold is zero, the witness list is empty,
    /// or the contribution (weight) of a witness is zero.
    pub fn witness(mut self, witness: &Witness) -> anyhow::Result<Self> {
        if witness.threshold == 0 {
            bail!("witness threshold must be greater than zero.");
        }
        if witness.witnesses.is_empty() {
            bail!("witness witness list must not be empty.");
        }
        for w in &witness.witnesses {
            if !w.id.starts_with("did:key:") {
                bail!("witness id must be a 'did:key:'.");
            }
            if w.weight == 0 {
                bail!("witness weight must be greater than zero.");
            }
        }
        self.params.witness = Some(witness.clone());
        Ok(self)
    }

    /// Construct the `did:webvh` document and log entries.
    #[must_use]
    pub fn build(self) -> CreateResult {
        let document = self.doc_builder.build();
        let _initial_log_entry = DidLogEntry {
            version_id: SCID_PLACEHOLDER.to_string(),
            version_time: chrono::Utc::now(),
            parameters: self.params,
            state: document,
            ..Default::default()
        };

        todo!()
    }
}
