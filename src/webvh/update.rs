//! Update operation for the `did:webvh` method.

use anyhow::bail;
use chrono::Utc;
use credibil_infosec::Signer;
use multibase::Base;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::{Document, Resolvable};

use super::{
    DidLog, DidLogEntry, Witness, WitnessEntry, resolve::resolve_log, verify::validate_witness,
};

/// Builder to update a DID document and associated log entry.
///
/// Use this to construct an [`UpdateResult`].
pub struct UpdateBuilder<S, D> {
    update_keys: Vec<String>,
    portable: bool,
    next_key_hashes: Option<Vec<String>>,
    witness: Option<Witness>,
    ttl: u64,

    log: DidLog,
    signer: S,
    doc: D,
}

/// Builder does not have a signer (can't build).
pub struct WithoutSigner;

/// Builder has a signer (can build).
pub struct WithSigner<'a, S: Signer>(pub &'a S);

/// Builder does not have a document (can't build).
#[derive(Clone, Debug)]
pub struct WithoutDocument;

/// Builder has a document (can build).
#[derive(Clone, Debug)]
pub struct WithDocument(Document);

impl UpdateBuilder<WithoutSigner, WithoutDocument> {
    /// Create a new `UpdateBuilder` populated with the current log entries.
    ///
    /// The log entries must be valid so this is tested, including verifying
    /// the witness proofs if provided. (To skip witness verification, pass None
    /// for the `witness_proofs` parameter.)
    ///
    /// # Errors
    /// Returns an error if the log entries are not valid.
    pub async fn from(
        log: &[DidLogEntry], witness_proofs: Option<&[WitnessEntry]>,
    ) -> anyhow::Result<Self> {
        // Validate the current log entries by resolving the DID document.
        let _ = resolve_log(log, witness_proofs, None).await?;
        let Some(last_entry) = log.last() else {
            anyhow::bail!("log must not be empty.");
        };

        Ok(Self {
            update_keys: last_entry.parameters.update_keys.clone(),
            portable: last_entry.parameters.portable,
            next_key_hashes: last_entry.parameters.next_key_hashes.clone(),
            witness: last_entry.parameters.witness.clone(),
            ttl: last_entry.parameters.ttl,

            log: log.to_vec(),
            doc: WithoutDocument,
            signer: WithoutSigner,
        })
    }

    /// Add the new DID document to the builder.
    ///
    /// # Errors
    /// Checks the SCID hasn't changed and the document location hasn't changed
    /// unless the original log entry allowed portability.
    pub fn document(
        &self, document: &Document,
    ) -> anyhow::Result<UpdateBuilder<WithoutSigner, WithDocument>> {
        // Check the DID location hasn't changed unless the original log entry
        // allowed portability. If the location has changed, the SCID must be
        // unchanged.
        let Some(last_entry) = self.log.last() else {
            anyhow::bail!("log must not be empty.");
        };
        if last_entry.state.id != document.id {
            if !last_entry.parameters.portable {
                anyhow::bail!("location has changed for non-portable DID.");
            }
            let parts = last_entry.state.id.split(':').collect::<Vec<&str>>();
            if parts.len() < 4 {
                anyhow::bail!("invalid DID format.");
            }
            let starts_with = format!("did:webvh:{}:", parts[2]);
            if !document.id.starts_with(&starts_with) {
                anyhow::bail!("SCID has changed for portable DID.");
            }
        }
        Ok(UpdateBuilder {
            update_keys: self.update_keys.clone(),
            portable: self.portable,
            next_key_hashes: self.next_key_hashes.clone(),
            witness: self.witness.clone(),
            ttl: self.ttl,

            log: self.log.clone(),
            doc: WithDocument(document.clone()),
            signer: WithoutSigner,
        })
    }
}

impl UpdateBuilder<WithoutSigner, WithDocument> {
    /// Rotate the update keys.
    ///
    /// The new update keys provided, when hashed, must match the hash of the
    /// current next key hashes. If there are no next key hashes on the current
    /// log entry it is assumed no pre-rotation strategy is being used and the
    /// new update keys will be applied regardless.
    ///
    /// The `new_update_keys` parameter is a list of public keys whose private
    /// key counterparts are authorized to sign DID log entries. They should be
    /// provided in bytes format.
    ///
    /// The `new_next_keys` parameter is a list of public keys whose private key
    /// counterparts will be authorized to sign update operations on subsequent
    /// key rotations. They should be provided in multibase-encoded format
    /// (this function will calculate their hashes).
    ///
    /// If key pre-rotation is not required for future updates set
    /// `new_next_keys` to an empty list.
    ///
    /// # Note
    /// The new update keys must not be used to sign the new log entry. Only
    /// the current update keys should be used to sign the new log entry. This
    /// will be checked on the build operation.
    ///
    /// # Errors
    /// If the hashed new update keys do not match the current next key hashes
    /// an error is returned (unless there are no next key hashes on the
    /// current log entry - pre-rotation not required).
    pub fn rotate_keys(
        mut self, new_update_keys: &[&str], new_next_keys: &[&str],
    ) -> anyhow::Result<Self> {
        // Check the new update keys hash to the current next key hashes.
        if let Some(next_key_hashes) = &self.next_key_hashes {
            for new_key in new_update_keys {
                let digest = sha2::Sha256::digest(new_key.as_bytes());
                let hash = multibase::encode(Base::Base58Btc, digest.as_slice());
                if !next_key_hashes.contains(&hash) {
                    bail!("new update keys do not match current next key hashes.");
                }
            }
        }

        self.update_keys = new_update_keys.iter().map(std::string::ToString::to_string).collect();
        if new_next_keys.is_empty() {
            self.next_key_hashes = None;
        } else {
            self.next_key_hashes = Some(
                new_next_keys
                    .iter()
                    .map(|key| {
                        let digest = sha2::Sha256::digest(key.as_bytes());
                        multibase::encode(Base::Base58Btc, digest.as_slice())
                    })
                    .collect(),
            );
        }

        Ok(self)
    }

    /// Set the DID to be portable or not. (Will inherit the current setting
    /// unless overridden here.)
    #[must_use]
    pub const fn portable(mut self, portable: bool) -> Self {
        self.portable = portable;
        self
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

    /// Set the permissable cache time in seconds for the DID. Will stay the
    /// same as the current log entry if not overridden here. Defaults to 0 if
    /// not previously set.
    #[must_use]
    pub const fn ttl(mut self, ttl: u64) -> Self {
        self.ttl = ttl;
        self
    }

    /// Add a signer to the builder.
    #[must_use]
    pub fn signer<S: Signer>(self, signer: &S) -> UpdateBuilder<WithSigner<'_, S>, WithDocument> {
        UpdateBuilder {
            update_keys: self.update_keys,
            portable: self.portable,
            next_key_hashes: self.next_key_hashes,
            witness: self.witness,
            ttl: self.ttl,

            log: self.log,
            doc: self.doc,
            signer: WithSigner(signer),
        }
    }
}

impl<S: Resolvable> UpdateBuilder<WithSigner<'_, S>, WithDocument> {
    /// Build the new log entry.
    ///
    /// Provide a `Provable` `Signer` to construct a data integrity proof. To
    /// add more proofs, call the `sign` method on the log entry after building.
    ///
    /// # Errors
    ///
    /// Will fail if secondary algorithms fail such as generating a hash of the
    /// log entry to calculate the version ID. Will also fail if the provided
    /// signer fails to sign the log entry.
    pub async fn build(&self) -> anyhow::Result<UpdateResult> {
        let mut log = self.log.clone();
        let Some(last_entry) = log.last() else {
            anyhow::bail!("log must not be empty.");
        };

        let mut params = last_entry.parameters.clone();
        params.update_keys.clone_from(&self.update_keys);
        params.portable = self.portable;
        params.next_key_hashes.clone_from(&self.next_key_hashes);
        params.witness.clone_from(&self.witness);
        params.ttl = self.ttl;

        let version_time = self
            .doc
            .0
            .did_document_metadata
            .as_ref()
            .map_or_else(Utc::now, |m| m.updated.unwrap_or_else(Utc::now));
        let mut entry = DidLogEntry {
            version_id: last_entry.version_id.clone(),
            version_time,
            parameters: params.clone(),
            state: self.doc.0.clone(),
            proof: vec![],
        };

        let entry_hash = entry.hash()?;
        let parts = last_entry.version_id.split('-').collect::<Vec<&str>>();
        if parts.len() != 2 {
            anyhow::bail!("unexpected version ID format.");
        }
        let mut version_number = parts[0].parse::<u64>()?;
        version_number += 1;
        entry.version_id = format!("{version_number}-{entry_hash}");

        // Sign (adds a proof to the log entry).
        entry.sign(self.signer.0).await?;

        log.push(entry);

        Ok(UpdateResult {
            did: self.doc.0.id.clone(),
            document: self.doc.0.clone(),
            log,
        })
    }
}

/// Output of an `update` operation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UpdateResult {
    /// The `did:webvh` DID.
    pub did: String,

    /// The `did:webvh` document.
    pub document: Document,

    /// Version history log consisting of the original log appended with the
    /// entry describing the update operation.
    pub log: Vec<DidLogEntry>,
}
