//! # DID Key
//!
//! The `did:key` method is a DID method for static cryptographic keys. At its
//! core, it is based on expanding a cryptographic public key into a DID
//! Document.
//!
//! See:
//!
//! - <https://w3c-ccg.github.io/did-method-key>
//! - <https://w3c.github.io/did-resolution>

pub mod operator;
pub mod resolver;
mod resolve;
pub mod url;

pub use resolve::*;

/// `DidKey` provides a type for implementing `did:key` operation and 
/// resolution methods. 
/// TODO: Remove this. Just need the namespace, not a receiver.
#[allow(clippy::module_name_repetitions)]
pub struct DidKey;
