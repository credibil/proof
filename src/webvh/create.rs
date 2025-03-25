//! Create operation for the `did:webvh` method.
//!
use anyhow::bail;
use chrono::Utc;
use credibil_infosec::{Signer, proof::w3c::Proof};
use serde::{Deserialize, Serialize};

use crate::{
    Document, KeyPurpose,
    core::Kind,
    document::{Service, VerificationMethod},
    operation::document::DocumentBuilder,
};

use super::{
    url::parse_url, verify::validate_witness, DidLogEntry, Parameters, Witness, BASE_CONTEXT, METHOD, SCID_PLACEHOLDER, VERSION
};

/// Builder to create a new `did:webvh` document and associated DID url and log.
///
/// Use this to construct a `CreateResult`.
pub struct CreateBuilder<U, K, V> {
    host_and_path: U,
    update_keys: K,
    verification_methods: V,

    method: String,
    scid: String,
    portable: bool,
    next_key_hashes: Option<Vec<String>>,
    witness: Option<Witness>,
    ttl: u64,

    controller: String,
    db: DocumentBuilder,
    proof: Proof,
}

// Typestate state guards for `CreateBuilder`.

/// The `CreateBuilder` is without an HTTP URL.
pub struct WithoutUrl;
/// The `CreateBuilder` has an HTTP URL.
pub struct WithUrl;
/// The `CreateBuilder` is without update keys.
pub struct WithoutUpdateKeys;
/// The `CreateBuilder` has update keys.
pub struct WithUpdateKeys(Vec<String>);
/// The `CreateBuilder` is without verification methods.
pub struct WithoutVerificationMethods;
/// The `CreateBuilder` has verification methods.
#[derive(Clone)]
pub struct WithVerificationMethods;

impl<U, K, V> CreateBuilder<U, K, V> {
    /// Create a new `CreateBuilder`.
    #[must_use]
    pub fn new() -> CreateBuilder<WithoutUrl, WithoutUpdateKeys, WithoutVerificationMethods> {
        CreateBuilder {
            host_and_path: WithoutUrl,
            update_keys: WithoutUpdateKeys,
            verification_methods: WithoutVerificationMethods,

            method: format!("did:{METHOD}:{VERSION}"),
            scid: SCID_PLACEHOLDER.to_string(),
            portable: false,
            next_key_hashes: None,
            witness: None,
            ttl: 0,

            controller: String::new(),
            db: DocumentBuilder::default(),
            proof: Proof::default(),
        }
    }
}

impl<U, K, V> CreateBuilder<U, K, V> {
    /// Retrieve the current document id (DID) from the builder.
    ///
    /// Note this will have a preliminary value based on the `SCID` placeholder
    /// and will be replaced during execution of the `build` method.
    #[must_use]
    pub fn did(&self) -> &str {
        self.db.did()
    }
}

impl CreateBuilder<WithoutUrl, WithoutUpdateKeys, WithoutVerificationMethods> {
    /// Add the hosting URL for the DID log.
    ///
    /// The provided url should be a valid HTTP URL.
    ///
    /// Valid examples:
    /// - `https://example.com`
    /// - `http://example.com/custom/path/`
    /// - `https://example.com:8080`
    ///
    /// If the log is to be hosted on a sub-path, the path should be included.
    /// Otherwise it is assumed the log is hosted at
    /// `https://<host>/.well-known/did.jsonl` and you SHOULD NOT include the
    /// `/.well-known` path.
    ///
    /// # Errors
    ///
    /// Will fail if the URL cannot be parsed into the host and path portion of
    /// a `did:webvh` DID.
    pub fn url(
        self, url: &str,
    ) -> anyhow::Result<CreateBuilder<WithUrl, WithoutUpdateKeys, WithoutVerificationMethods>> {
        let host_and_path = parse_url(url)?;
        let controller = format!("did:{METHOD}:{SCID_PLACEHOLDER}:{host_and_path}");
        let mut db = DocumentBuilder::new(&controller);
        for ctx in &BASE_CONTEXT {
            db = db.context(&Kind::String((*ctx).to_string()));
        }
        Ok(CreateBuilder {
            host_and_path: WithUrl,
            update_keys: self.update_keys,
            verification_methods: self.verification_methods,

            scid: self.scid,
            method: self.method,
            portable: self.portable,
            next_key_hashes: self.next_key_hashes,
            witness: self.witness,
            ttl: self.ttl,

            controller,
            db,
            proof: self.proof,
        })
    }
}

impl CreateBuilder<WithUrl, WithoutUpdateKeys, WithoutVerificationMethods> {
    /// Add an array of public keys associated with private keys authorized to
    /// sign log entries for this DID. Multikey format.
    ///
    /// # Errors
    ///
    /// Will fail if the update keys are empty.
    pub fn update_keys(
        self, update_keys: Vec<String>,
    ) -> anyhow::Result<CreateBuilder<WithUrl, WithUpdateKeys, WithoutVerificationMethods>> {
        if update_keys.is_empty() {
            bail!("update keys must not be empty.");
        }
        Ok(CreateBuilder {
            host_and_path: self.host_and_path,
            update_keys: WithUpdateKeys(update_keys),
            verification_methods: self.verification_methods,

            scid: self.scid,
            method: self.method,
            portable: self.portable,
            next_key_hashes: self.next_key_hashes,
            witness: self.witness,
            ttl: self.ttl,

            controller: self.controller,
            db: self.db,
            proof: self.proof,
        })
    }
}

impl CreateBuilder<WithUrl, WithUpdateKeys, WithoutVerificationMethods> {
    /// Add the first verification method to be included in the DID document.
    ///
    /// At least one verification method is required to build the output result.
    ///
    /// It is recommended to use
    /// [`operation::document::VerificationMethodBuilder`] to construct a
    /// verification method.
    ///
    /// # Errors
    ///
    /// Will fail if the verification method infornation is invalid.
    pub fn verification_method(
        self, verification_method: &Kind<VerificationMethod>, purpose: &KeyPurpose,
    ) -> anyhow::Result<CreateBuilder<WithUrl, WithUpdateKeys, WithVerificationMethods>> {
        let db = self.db.verification_method(verification_method, purpose)?;

        Ok(CreateBuilder {
            host_and_path: self.host_and_path,
            update_keys: self.update_keys,
            verification_methods: WithVerificationMethods,

            scid: self.scid,
            method: self.method,
            portable: self.portable,
            next_key_hashes: self.next_key_hashes,
            witness: self.witness,
            ttl: self.ttl,

            controller: self.controller,
            db,
            proof: self.proof,
        })
    }
}

impl CreateBuilder<WithUrl, WithUpdateKeys, WithVerificationMethods> {
    /// Set the DID to be portable (defaults to not portable)
    #[must_use]
    pub const fn portable(mut self, portable: bool) -> Self {
        self.portable = portable;
        self
    }

    /// Add a next key hash to the list of next key hashes if required.
    #[must_use]
    pub fn next_key_hash(mut self, next_key_hash: String) -> Self {
        self.next_key_hashes.get_or_insert(vec![]).push(next_key_hash);
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

    /// Add another verification method to be included in the DID document.
    ///
    /// This can be called multiple times to add more verification methods.
    ///
    /// It is recommended to use
    /// [`operation::document::VerificationMethodBuilder`] to construct a
    /// verification method.
    ///
    /// # Errors
    ///
    /// Will fail if the verification method infornation is invalid.
    pub fn verification_method(
        mut self, verification_method: &Kind<VerificationMethod>, purpose: &KeyPurpose,
    ) -> anyhow::Result<Self> {
        self.db = self.db.verification_method(verification_method, purpose)?;
        Ok(self)
    }

    /// Add an optional service endpoint to the DID document.
    ///
    /// This can be called multiple times to add more service endpoints.
    #[must_use]
    pub fn service(mut self, service: &Service) -> Self {
        self.db = self.db.service(service);
        self
    }

    /// Add any additional context to the DID document.
    ///
    /// There is no need to call this for the default contexts for this DID
    /// method - these will be added automatically. Use this to add any
    /// additional contexts required by your specific use case.
    ///
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
        // Construct a preliminary document.
        let doc = self.db.build();

        // Construct preliminary parameters.
        let params = Parameters {
            method: self.method,
            scid: self.scid,
            update_keys: self.update_keys.0,
            portable: self.portable,
            next_key_hashes: self.next_key_hashes,
            witness: self.witness,
            deactivated: false,
            ttl: self.ttl,
        };

        // Construct an initial log entry.
        let version_time = doc.did_document_metadata.as_ref().map_or_else(Utc::now, |m| m.created);
        let initial_log_entry = DidLogEntry {
            version_id: SCID_PLACEHOLDER.to_string(),
            version_time,
            parameters: params.clone(),
            state: doc.clone(),
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
