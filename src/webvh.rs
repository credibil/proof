//! # DID Web with Verifiable History
//! 
//! The `did:webvh` method is an enhanced version of the `did:web` method that
//! includes the ability to resolve a full history of the DID document through
//! a chain of updates.
//! 
//! See: <https://identity.foundation/didwebvh/next/>

use chrono::{DateTime, Utc};
use credibil_infosec::proof::w3c::Proof;
use serde::{Deserialize, Serialize};

use crate::Document;

pub mod operator;
pub mod resolver;

// pub (crate) const SCID_PLACEHOLDER: &'static str = "{SCID}";
// pub (crate) const METHOD: &'static str = "webvh";
// pub (crate) const VERSION: &'static str = "0.5";
// pub (crate) const BASE_CONTEXT: [&'static str; 2] = [
//     "https://www.w3.org/ns/did/v1",
//     "https://w3id.org/security/multikey/v1",
// ];

// pub (crate) fn protocol() -> String {
//     format!("did:{METHOD}:{VERSION}")
// }

/// `DidWebVh` provides a type for implementing `did:webvh` operation and
/// resolution methods.
pub struct DidWebVh;

/// `DidLogEntry` is an entry in the `did.jsonl` log file denoting the
/// sequential changes to a DID document.
///
/// <https://identity.foundation/didwebvh/#the-did-log-file>
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidLogEntry {
    /// DID version number starting at 1 and incrementing by one per DID
    /// version, a literal dash `-`, and the `entryHash`.
    pub version_id: String,

    /// A UTC timestamp in ISO 8601 format.
    pub version_time: DateTime<Utc>,

    /// Log entry parameters.
    pub parameters: Parameters,

    /// The resolved DID document for this version.
    pub state: Document,

    /// Signed data integrity proof.
    pub proof: Proof,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Parameters {
    /// The `did:webvh` specification version to use when processing a DID's
    /// log file.
    pub method: String,

    /// The value of the self-certifying identifier (SCID) for this DID.
    pub scid: String,

    /// An array of public keys associated with private keys authorized to sign
    /// log entries for this DID. Multikey format.
    pub update_keys: Vec<String>,

    /// Can the DID be renamed and hosted on a different domain?
    pub portable: bool,

    /// Hashes of ublic keys that may be added to the update keys in subsequent
    /// key rotation operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_key_hashes: Option<Vec<String>>,

    /// Parameters for declaring witnesses for the DID and the process for
    /// updating the DID via collaboration with witnesses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<Witness>,

    /// Indicator of whether the DID has been deactivated.
    pub deactivated: bool,

    /// Maximum time in seconds the DID should be cached before a full
    /// resolution must be performed.
    pub ttl: u64,
}

/// A list of IDs of witnesses and their contribution to verification of changes
/// to the DID document.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Witness {
    /// The total of the weights of witnesses required to approve a change.
    pub threshold: u64,

    /// The list of witnesses and their contributing weights.
    pub witnesses: Vec<WitnessWeight>,
}

/// The weight a witness contributes to the approval of a DID update.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WitnessWeight {
    /// The DID of the witness using the `did:key` method.
    pub id: String,

    /// The weight of the witness.
    pub weight: u64,
}

/// Entry in the `did-witness.json` file.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WitnessEntry {
    /// Version ID of the DID log entry to which the witnesses' proof applies.
    pub version_id: String,

    /// Witnesses' proof of the DID log entry using the `eddsa-jcs-2022`
    /// cryptosuite.
    pub proof: Vec<Proof>,
}