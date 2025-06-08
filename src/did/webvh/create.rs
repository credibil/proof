//! Create operation for the `did:webvh` method.

use anyhow::{Result, bail};
use chrono::Utc;
use multibase::Base;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use super::verify::validate_witness;
use super::{DidLogEntry, Parameters, SCID, VERSION, Witness};
use crate::Signature;
use crate::did::webvh::default_did;
use crate::did::{Document, DocumentBuilder};

/// Builder to create a new `did:webvh` document and associated DID url and log.
///
/// Use this to construct a `CreateResult`.
pub struct CreateBuilder<U, S, D> {
    url: String,
    method: String,
    scid: String,
    portable: bool,
    next_key_hashes: Option<Vec<String>>,
    witness: Option<Witness>,
    ttl: u64,
    update_keys: U,
    signer: S,
    document: D,
}

/// Builder does not have update keys (can't build).
pub struct NoUpdateKeys;

/// Builder has update keys (can build).
pub struct WithUpdateKeys(Vec<String>);

/// Builder does not have a signer (can't build).
pub struct NoSigner;

/// Builder has a signer (can build).
pub struct WithSigner<'a, S: Signature>(pub &'a S);

/// Builder does not have a document (can't build).
pub struct NoDocument;

/// Builder has a document (can build).
pub struct WithDocument(DocumentBuilder);

impl CreateBuilder<NoUpdateKeys, NoSigner, NoDocument> {
    /// Create a new `CreateBuilder`.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method: format!("did:webvh:{VERSION}"),
            scid: SCID.to_string(),
            portable: false,
            next_key_hashes: None,
            witness: None,
            ttl: 0,
            update_keys: NoUpdateKeys,
            signer: NoSigner,
            document: NoDocument,
        }
    }

    /// Add a populated [`DocumentBuilder`] instance.
    #[must_use]
    pub fn document(
        self, builder: DocumentBuilder,
    ) -> CreateBuilder<NoUpdateKeys, NoSigner, WithDocument> {
        CreateBuilder {
            url: self.url,
            method: self.method,
            scid: self.scid,
            portable: self.portable,
            next_key_hashes: self.next_key_hashes,
            witness: self.witness,
            ttl: self.ttl,
            update_keys: NoUpdateKeys,
            signer: NoSigner,
            document: WithDocument(builder),
        }
    }
}

impl CreateBuilder<NoUpdateKeys, NoSigner, WithDocument> {
    /// Add update keys.
    ///
    /// Update keys are the multibase-encoded public keys that can be used by
    /// a controller to sign log entries for the DID.
    ///
    /// # Errors
    /// Will fail if the update keys are empty.
    #[must_use]
    pub fn update_keys(
        self, update_keys: Vec<String>,
    ) -> CreateBuilder<WithUpdateKeys, NoSigner, WithDocument> {
        CreateBuilder {
            url: self.url,
            method: self.method.clone(),
            scid: self.scid.clone(),
            portable: self.portable,
            next_key_hashes: self.next_key_hashes.clone(),
            witness: self.witness.clone(),
            ttl: self.ttl,
            update_keys: WithUpdateKeys(update_keys),
            signer: NoSigner,
            document: self.document,
        }
    }
}

impl CreateBuilder<WithUpdateKeys, NoSigner, WithDocument> {
    /// Add a signer to the builder.
    #[must_use]
    pub fn signer<S: Signature>(
        self, signer: &S,
    ) -> CreateBuilder<WithUpdateKeys, WithSigner<'_, S>, WithDocument> {
        CreateBuilder {
            url: self.url,
            method: self.method,
            scid: self.scid,
            portable: self.portable,
            next_key_hashes: self.next_key_hashes,
            witness: self.witness,
            ttl: self.ttl,
            update_keys: self.update_keys,
            signer: WithSigner(signer),
            document: self.document,
        }
    }
}

impl<U, S, D> CreateBuilder<U, S, D> {
    /// Set the DID to be portable or not (defaults to not portable).
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
    #[must_use]
    pub fn witness(mut self, witness: &Witness) -> Self {
        self.witness = Some(witness.clone());
        self
    }

    /// Set the permissable cache time in seconds for the DID. Defaults to 0 if
    /// not set here.
    #[must_use]
    pub const fn ttl(mut self, ttl: u64) -> Self {
        self.ttl = ttl;
        self
    }
}

impl<S: Signature> CreateBuilder<WithUpdateKeys, WithSigner<'_, S>, WithDocument> {
    /// Build the new log entry.
    ///
    /// Provide a `Provable` `Signer` to construct a data integrity proof. To
    /// add more proofs, call the `sign` method on the log entry after building.
    ///
    /// # Errors
    ///
    /// Will fail if secondary algorithms fail such as generating a hash of the
    /// log entry to calculate the `SCID` or version ID, or failing to replace
    /// the placeholder `SCID` with the calculated one. Will also fail if the
    /// provided signer fails to sign the log entry.
    pub async fn build(self) -> Result<CreateResult> {
        let did = default_did(&self.url)?;
        let document = self.document.0.build(did)?;

        //  update keys cannot be empty.
        if self.update_keys.0.is_empty() {
            bail!("update keys must not be empty.");
        }
        if let Some(witness) = &self.witness {
            validate_witness(witness)?;
        }

        // Construct preliminary parameters.
        let params = Parameters {
            method: self.method.clone(),
            scid: self.scid.clone(),
            update_keys: self.update_keys.0.clone(),
            portable: self.portable,
            next_key_hashes: self.next_key_hashes.clone(),
            witness: self.witness.clone(),
            deactivated: false,
            ttl: self.ttl,
        };

        // Construct an initial log entry.
        let version_time =
            document.did_document_metadata.as_ref().map_or_else(Utc::now, |m| m.created);
        let initial_log_entry = DidLogEntry {
            version_id: SCID.to_string(),
            version_time,
            parameters: params.clone(),
            state: document,
            proof: vec![],
        };

        // Create the SCID from the hash of the log entry with the `{SCID}`
        // placeholder.
        let initial_hash = initial_log_entry.hash()?;

        // Make a log entry from the placeholder, replacing the placeholder SCID
        // with the calculated SCID (content hash).
        let initial_string = serde_json::to_string(&initial_log_entry)?;
        let replaced = initial_string.replace(SCID, &initial_hash);
        let mut entry = serde_json::from_str::<DidLogEntry>(&replaced)?;

        // Construct a log entry version.
        let entry_hash = entry.hash()?;
        entry.version_id = format!("1-{entry_hash}");

        // Sign (adds a proof to the log entry).
        entry.sign(self.signer.0).await?;

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
