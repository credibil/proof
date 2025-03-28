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

/// Receiver for the `did:jwk` method.
/// TODO: Remove this. Just need the namespace, not a struct.
#[allow(clippy::module_name_repetitions)]
pub struct DidJwk;
