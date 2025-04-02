//! # DID Web
//!
//! The `did:web` method uses a web domain's reputation to confer trust.
//!
//! See:
//!
//! - <https://w3c-ccg.github.io/did-method-web>
//! - <https://w3c.github.io/did-resolution>

pub mod operator;
pub mod resolver;
mod resolve;

pub use resolve::*;

/// `DidWeb` provides a type for implementing `did:web` operation and 
/// resolution methods.
#[allow(clippy::module_name_repetitions)]
pub struct DidWeb;
