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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameters {}
