//! # DID Core
//! Types, traits and functions for working with Decentralized Identifiers (DIDs) and DID Documents.

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

pub(crate) mod document;
pub mod error;
pub mod hashing;
pub(crate) mod keys;
pub(crate) mod registrar;
pub(crate) mod resolver;
mod serde;
pub mod test_utils;

pub use document::context::{Context, DID_CONTEXT};
pub use document::patch::{Action, Document, Patch, VmWithPurpose};
pub use document::service::{check_services, Endpoint, Service};
pub use document::verification_method::{KeyPurpose, VerificationMethod};
pub use document::DidDocument;
pub use keys::keyring::KeyRing;
pub use keys::signer::Signer;
pub use keys::{Algorithm, Jwk, KeyOperation};
pub use registrar::{OperationType, Registrar};
pub use resolver::{DocumentMetadata, Resolution, ResolutionMetadata, Resolver};

/// Result type for DID Core.
pub type Result<T, E = error::Error> = core::result::Result<T, E>;
