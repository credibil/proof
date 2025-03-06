//! # DID Web with Verifiable History
//! 
//! The `did:webvh` method is an enhanced version of the `did:web` method that
//! includes the ability to resolve a full history of the DID document through
//! a chain of updates.
//! 
//! See: <https://identity.foundation/didwebvh/next/>

pub mod operator;
pub mod resolver;

/// `DidWebVh` provides a type for implementing `did:webvh` operation and
/// resolution methods.
pub struct DidWebVh;