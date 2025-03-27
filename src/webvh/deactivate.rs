//! Deactivate (revoke) operation for the `did:webvh` method.
//! 

use anyhow::bail;
use chrono::Utc;
use credibil_infosec::Signer;
use serde::{Deserialize, Serialize};

use crate::Document;

use super::{verify::validate_witness, DidLogEntry, Witness};

/// Builder for deactivating a DID document and associated log entry (or 2
/// entries if there is key rotation).
pub struct DeactivateBuilder {
    witness: Option<Witness>,
    log: Vec<DidLogEntry>,
    doc: Document,
}

impl DeactivateBuilder {
    /// Crate a new `DeactivateBuilder` populated with the current log entries.
    /// 
    /// It is assumed that the DID document is resolved from the last log entry
    /// otherwise an update operation should be used ahead of this.
    /// 
    /// # Errors
    /// Will fail if the log entries are not populated.
    pub fn new(log: &[DidLogEntry]) -> anyhow::Result<Self> {
        let Some(last_entry) = log.last() else {
            bail!("log must not be empty.");
        };
        Ok(Self {
            witness: last_entry.parameters.witness.clone(),
            log: log.to_vec(),
            doc: last_entry.state.clone(),
        })
    }

    /// Add a set of witnesses expected to provide proofs for this update.
    ///
    /// If this function is not called, the witness information from the last
    /// log entry will be used.
    ///
    /// To remove witnesses from this update, call the `remove_witness`
    /// function.
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

    /// Remove witnesses from this update.
    #[must_use]
    pub fn remove_witness(mut self) -> Self {
        self.witness = None;
        self
    }

    /// Build the new log entry/entries.
    /// 
    /// If the last log entry has a non-empty `next_key_hashes`, two log entries
    /// will be created: one to nullify the `next_key_hashes` and one to
    /// deactivate the DID.
    /// 
    /// Provide a `Signer` to construct a data integrity proof. To add more
    /// proofs, call the `sign` method on the log entry/entries after building.
    /// 
    /// # Errors
    /// Will fail if secondary algorithms fail such as generating a hash of the
    /// log entry to calculate the version ID. Will also fail if the provided
    /// signer fails to sign the log entry.
    pub async fn build(&self, signer: &impl Signer) -> anyhow::Result<DeactivateResult> {
        let mut log = self.log.clone();
        let Some(last_entry) = log.last() else {
            bail!("log must not be empty.");
        };
        let mut last_entry = last_entry.clone();

        let mut params = last_entry.parameters.clone();
        params.witness.clone_from(&self.witness);

        if last_entry.parameters.next_key_hashes.is_some() {
            params.next_key_hashes = None;
            let mut entry = DidLogEntry {
                version_id: last_entry.version_id.clone(),
                version_time: Utc::now(),
                parameters: params.clone(),
                state: self.doc.clone(),
                proof: vec![],
            };

            let entry_hash = entry.hash()?;
            let parts = last_entry.version_id.split('-').collect::<Vec<&str>>();
            if parts.len() != 2 {
                bail!("log entry version ID has an unexpected format");
            }
            let mut version_number = parts[0].parse::<u64>()?;
            version_number += 1;
            entry.version_id = format!("{version_number}-{entry_hash}");

            entry.sign(signer).await?;
            last_entry.clone_from(&entry);
            log.push(entry);
        }

        params.update_keys = Vec::new();
        params.next_key_hashes = None;
        params.deactivated = true;
        let mut md = self.doc.did_document_metadata.clone().unwrap_or_default();
        md.updated = Some(Utc::now());
        md.deactivated = Some(true);
        let mut doc = self.doc.clone();
        doc.did_document_metadata = Some(md);

        let mut entry = DidLogEntry {
            version_id: last_entry.version_id.clone(),
            version_time: Utc::now(),
            parameters: params.clone(),
            state: doc.clone(),
            proof: vec![],
        };

        let entry_hash = entry.hash()?;
        let parts = last_entry.version_id.split('-').collect::<Vec<&str>>();
        if parts.len() != 2 {
            bail!("unexpected version ID format");
        }
        let mut version_number = parts[0].parse::<u64>()?;
        version_number += 1;
        entry.version_id = format!("{version_number}-{entry_hash}");

        entry.sign(signer).await?;
        log.push(entry);

        Ok(DeactivateResult {
            did: doc.id.clone(),
            document: doc,
            log,
        })
    }
}

/// Output of an `deactivate` operation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DeactivateResult {
    /// The `did:webvh` DID.
    pub did: String,

    /// The `did:webvh` document.
    pub document: Document,

    /// Version history log consisting of the original log appended with the
    /// entry describing the update operation.
    pub log: Vec<DidLogEntry>,
}
