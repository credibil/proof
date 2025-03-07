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
use url::Url;

use crate::Document;

pub mod operator;
pub mod resolver;

/// `DidWebVh` provides a type for implementing `did:webvh` operation and
/// resolution methods.
pub struct DidWebVh;

/// `DidWebVhUrl` provides a type for constructing URLs for the `did:webvh`
/// method.
pub struct DidWebVhUrl {
    host_and_path: String,
    scid: Option<String>,
}

impl DidWebVhUrl {
    /// Create a new `DidWebVhUrl` builder by providing a host and path.
    /// 
    /// The provided url should be a valid HTTP URL.
    /// 
    /// Valid examples:
    /// - `https://example.com`
    /// - `http://example.com/custom/path/`
    /// - `https://example.com:8080`
    ///
    /// # Panics
    /// 
    /// Panics if the url is not a valid URL.
    /// 
    pub fn builder(url: &str) -> Self {
        // Parse the URL.
        let url = Url::parse(url).expect("invalid URL");
        let host_str = url.host_str().expect("no host in URL");
        let mut host = host_str.to_string();
        if let Some(port) = url.port() {
            host.push_str(&format!{"%3A{port}"});
        }
        if let Some(path) = url.path().strip_prefix('/') {
            if !path.is_empty() {
                let formatted_path = path.trim_end_matches('/');
                let formatted_path = formatted_path.replace('/', ":");
                host.push_str(&format!{":{formatted_path}"});
            }
        }
        Self {
            host_and_path: host,
            scid: None,
        }
    }

    /// Set the SCID for the DID URL.
    /// 
    /// This should not be called by default. The builder will generate a
    /// self-certifying identifier (SCID). This method is provided for cases
    /// where a specific SCID is required.
    pub fn with_scid(mut self, scid: &str) -> Self {
        self.scid = Some(scid.to_string());
        self
    }

    /// Build the DID URL.
    pub fn build(self) -> String {
        let scid = self.scid.unwrap_or_else(|| "{SCID}".to_string());
        format!("did:webvh:{scid}:{}", self.host_and_path)
    }

    // TODO: this.
    // fn generate_scid(&mut self) {
    //     // Generate a self-certifying identifier (SCID) if one is not provided.
    //     if self.scid.is_none() {
    //         self.scid = Some("".to_string());
    //     }
    // }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_webvh_url_builder() {
        let url = "https://example.com";
        let did_url = DidWebVhUrl::builder(url).build();
        assert_eq!(did_url, "did:webvh:{SCID}:example.com");

        let url = "http://example.com/custom/path/";
        let did_url = DidWebVhUrl::builder(url).build();
        assert_eq!(did_url, "did:webvh:{SCID}:example.com:custom:path");

        let url = "https://example.com:8080";
        let did_url = DidWebVhUrl::builder(url).build();
        assert_eq!(did_url, "did:webvh:{SCID}:example.com%3A8080");
    }
}