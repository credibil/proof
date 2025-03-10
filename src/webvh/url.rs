//! # DID Web with Verifiable History Operations
//! 
//! Implements Create, Read, Update, Delete (CRUD) operations for DID Web with
//! Verifiable History.
//! 
//! See <https://identity.foundation/didwebvh/next/>

use url::Url;

use crate::{CreateOptions, DidOperator, Document};

use super::DidWebVh;

impl DidWebVh {
    /// Create a new DID Document from the provided HTTP URL.
    /// 
    /// (A DID URL will be constructed from the HTTP URL).
    /// 
    /// # Errors
    /// 
    /// Will fail if the DID URL is not a valid or the verifying key is invalid.
    pub fn create(
        url: &str, _op: &impl DidOperator, _options: CreateOptions,
    ) -> crate::Result<Document> {
        let _did_str = DidWebVhUrl::builder(url).build();
        todo!()
    }

    /// Converts a `did:webvh` DID document to a `did:web` DID document.
    #[must_use]
    pub fn convert_to_web(_vh_doc: &Document) -> Document {
        todo!()
    }
}

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
            host.push_str(&format!("%3A{port}"));
        }
        if let Some(path) = url.path().strip_prefix('/') {
            if !path.is_empty() {
                let formatted_path = path.trim_end_matches('/');
                let formatted_path = formatted_path.replace('/', ":");
                host.push_str(&format!(":{formatted_path}"));
            }
        }
        Self {
            host_and_path: host,
            scid: None,
        }
    }

    // /// Set the SCID for the DID URL.
    // /// 
    // /// This should not be called by default. The builder will generate a
    // /// self-certifying identifier (SCID). This method is provided for cases
    // /// where a specific SCID is required.
    // pub fn with_scid(mut self, scid: &str) -> Self {
    //     self.scid = Some(scid.to_string());
    //     self
    // }

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
