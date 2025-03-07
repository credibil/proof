//! # DID Web with Verifiable History Operations
//! 
//! Implements Create, Read, Update, Delete (CRUD) operations for DID Web with
//! Verifiable History.
//! 
//! See <https://identity.foundation/didwebvh/next/>

use crate::{CreateOptions, DidOperator, Document};

use super::DidWebVh;

impl DidWebVh {
    /// Create a new DID Document from the provided `did:webvh` DID URL.
    /// 
    /// Use the helper functions in this module to construct a valid DID URL if
    /// needed.
    /// 
    /// # Errors
    /// 
    /// Will fail if the DID URL is not a valid or the verifying key is invalid.
    pub fn create(
        _url: &str, _op: &impl DidOperator, _options: CreateOptions,
    ) -> crate::Result<Document> {
        todo!()
    }
}