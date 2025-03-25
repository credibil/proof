//! Create operation for the `did:webvh` method.
//!
use anyhow::bail;
use chrono::Utc;
use credibil_infosec::Signer;
use multibase::Base;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::{Document, core::Kind};

use super::{
    BASE_CONTEXT, DidLogEntry, METHOD, Parameters, SCID_PLACEHOLDER, VERSION, Witness,
    verify::validate_witness,
};

/// Builder to create a new `did:webvh` document and associated DID url and log.
///
/// Use this to construct a `CreateResult`.
pub struct CreateBuilder {
    update_keys: Vec<String>,
    method: String,
    scid: String,
    portable: bool,
    next_key_hashes: Option<Vec<String>>,
    witness: Option<Witness>,
    ttl: u64,

    doc: Document,
}

impl CreateBuilder {
    /// Create a new `CreateBuilder`.
    ///
    /// Pass a document with a default DID and at least one update key.
    ///
    /// You can use a `DocumentBuilder` to construct the document using a DID
    /// constructed using the `default_did` function to construct one from the
    /// intended hosting URL. This will use `{SCID}` as a placeholder for the
    /// self-certifying identifier (SCID). This builder will calculate the
    /// required SCID and update the document with it as part of the build
    /// algorithm.
    ///
    /// Update keys are the multibase-encoded public keys that can be used by
    /// a constroller to sign log entries for the DID.
    ///
    /// # Errors
    ///
    /// Will fail if the update keys are empty or if the document ID does not
    /// resemble a `did:webvh:{SCID}:<host_and_path>` string.
    pub fn new(update_keys: &[&str], document: &Document) -> anyhow::Result<Self> {
        // The update keys cannot be empty.
        if update_keys.is_empty() {
            bail!("update keys must not be empty.");
        }
        // The document ID must resemble a `did:webvh:{SCID}:<host_and_path>`
        // string.
        if !document.id.starts_with(&format!("did:{METHOD}:{SCID_PLACEHOLDER}")) {
            bail!("document ID must start with 'did:{METHOD}:{SCID_PLACEHOLDER}'");
        }

        let mut doc = document.clone();

        // Ensure we have the base context on the document for this DID method.
        for ctx in &BASE_CONTEXT {
            let c = Kind::String((*ctx).to_string());
            if !document.context.contains(&c) {
                doc.context.push(c);
            }
        }

        Ok(Self {
            update_keys: update_keys.iter().map(std::string::ToString::to_string).collect(),

            method: format!("did:{METHOD}:{VERSION}"),
            scid: SCID_PLACEHOLDER.to_string(),
            portable: false,
            next_key_hashes: None,
            witness: None,
            ttl: 0,

            doc,
        })
    }

    /// Retrieve the current document id (DID) from the builder.
    ///
    /// Note this will have a preliminary value based on the `SCID` placeholder
    /// and will be replaced during execution of the `build` method.
    #[must_use]
    pub fn did(&self) -> String {
        self.doc.id.clone()
    }

    /// Set the DID to be portable (defaults to not portable)
    #[must_use]
    pub const fn portable(mut self, portable: bool) -> Self {
        self.portable = portable;
        self
    }

    /// Add a next key hash to the list of next key hashes if required.
    ///
    /// Pass in the multibase-encoded public key to be used as the next key and
    /// this function will carry out the hashing and encoding before adding it
    /// to the list of next key hashes.
    #[must_use]
    pub fn next_key(mut self, next_key_multi: &str) -> Self {
        let next_digest = sha2::Sha256::digest(next_key_multi.as_bytes());
        let next_hash = multibase::encode(Base::Base58Btc, next_digest.as_slice());
        self.next_key_hashes.get_or_insert(vec![]).push(next_hash);
        self
    }

    /// Add a set of witnesses to the create operation.
    ///
    /// # Errors
    ///
    /// Will fail if the witness threshold is zero, the witness list is empty,
    /// the contribution (weight) of a witness is zero, or the sum of
    /// contributions would never reach the threshold.
    pub fn witness(mut self, witness: &Witness) -> anyhow::Result<Self> {
        validate_witness(witness)?;
        self.witness = Some(witness.clone());
        Ok(self)
    }

    /// Set the permissable cache time in seconds for the DID. Defaults to 0 if
    /// not set here.
    #[must_use]
    pub const fn ttl(mut self, ttl: u64) -> Self {
        self.ttl = ttl;
        self
    }
    /// Build the `CreateResult`, providing a `Signer` to construct a data
    /// integrity proof.
    ///
    /// # Errors
    ///
    /// Will fail if secondary algorithms fail such as generating a hash of the
    /// log entry to calculate the `SCID` or failing to replace the placeholder
    /// `SCID` with the calculated one. Will also fail if the provided signer
    /// fails to sign the log entry.
    pub async fn build(self, signer: &impl Signer) -> anyhow::Result<CreateResult> {
        // Construct preliminary parameters.
        let params = Parameters {
            method: self.method,
            scid: self.scid,
            update_keys: self.update_keys,
            portable: self.portable,
            next_key_hashes: self.next_key_hashes,
            witness: self.witness,
            deactivated: false,
            ttl: self.ttl,
        };

        // Construct an initial log entry.
        let version_time =
            self.doc.did_document_metadata.as_ref().map_or_else(Utc::now, |m| m.created);
        let initial_log_entry = DidLogEntry {
            version_id: SCID_PLACEHOLDER.to_string(),
            version_time,
            parameters: params.clone(),
            state: self.doc.clone(),
            proof: vec![],
        };

        // Create the SCID from the hash of the log entry with the `{SCID}`
        // placeholder.
        let initial_hash = initial_log_entry.hash()?;

        // Make a log entry from the placeholder, replacing the placeholder SCID
        // with the calculated SCID (content hash).
        let initial_string = serde_json::to_string(&initial_log_entry)?;
        let replaced = initial_string.replace(SCID_PLACEHOLDER, &initial_hash);
        let mut entry = serde_json::from_str::<DidLogEntry>(&replaced)?;

        // Construct a log entry version.
        let entry_hash = entry.hash()?;
        entry.version_id = format!("1-{entry_hash}");

        // Sign (adds a proof to the log entry).
        entry.sign(signer).await?;

        Ok(CreateResult {
            did: entry.state.id.clone(),
            document: entry.state.clone(),
            log: vec![entry],
        })
    }
}

/// Output of a `create` operation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CreateResult {
    /// The `did:webvh` DID.
    pub did: String,

    /// The `did:webvh` document.
    pub document: Document,

    /// Version history log with the single created entry suitable for writing
    /// to a `did.jsonl` log file.
    pub log: Vec<DidLogEntry>,
}
