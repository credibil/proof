#![feature(let_chains)]

//! # DID Resolver
//!
//! This crate provides common utilities for the Vercre project and is not
//! intended to be used directly.
//!
//! The crate provides a DID Resolver trait and a set of default implementations
//! for resolving DIDs.
//!
//! See [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) fpr more.

// TODO: add support for the following:
//   key type: EcdsaSecp256k1VerificationKey2019 | JsonWebKey2020 |
// Ed25519VerificationKey2020 |             Ed25519VerificationKey2018 |
// X25519KeyAgreementKey2019   crv: Ed25519 | secp256k1 | P-256 | P-384 | p-521

mod core;
mod document;
mod error;
mod jwk;
mod key;
mod resolution;
mod web;

use std::future::Future;

pub use error::Error;
pub use resolution::{
    dereference, resolve, ContentType, Dereferenced, Metadata, Options, Resolved, Resource,
};
use vercre_infosec::PublicKeyJwk;

pub use crate::document::Document;

const ED25519_CODEC: [u8; 2] = [0xed, 0x01];
const X25519_CODEC: [u8; 2] = [0xec, 0x01];

/// Returns DID-specific errors.
pub type Result<T> = std::result::Result<T, Error>;

/// `DidResolver` is used to proxy the resolution of a DID document. Resolution
/// can either be local as in the case of `did:key`, or remote as in the case of
/// `did:web` or `did:dht`.
///
/// Implementers need only return the DID document specified by the url. This
/// may be by directly dereferencing the URL, looking up a local cache, or
/// fetching from a remote DID resolver.
///
/// For example, a DID resolver for `did:web` would fetch the DID document from
/// the specified URL. A DID resolver for `did:dht`should forward the request to
/// a remote DID resolver for the DHT network.
pub trait DidResolver: Send {
    /// Resolve the DID URL to a DID Document.
    ///
    /// # Errors
    ///
    /// Returns an error if the DID URL cannot be resolved.
    fn resolve(&self, url: &str) -> impl Future<Output = anyhow::Result<Document>> + Send;
}

/// DidOperator is used by implementers to provide material required for DID
/// document operations — creation, update, etc.
pub trait DidOperator: Send + Sync {
    /// Provides verification material to be used for the specified
    /// verification method.
    fn verification(&self, purpose: KeyPurpose) -> Option<PublicKeyJwk>;
}

/// The purpose the requested key material will be used for.
pub enum KeyPurpose {
    /// The document's `verification_method` field.
    VerificationMethod,

    /// The document's `authentication` field.
    Authentication,

    /// The document's `assertion_method` field.
    AssertionMethod,

    /// The document's `key_agreement` field.
    KeyAgreement,

    /// The document's `capability_invocation` field.
    CapabilityInvocation,

    /// The document's `capability_delegation` field.
    CapabilityDelegation,
}
