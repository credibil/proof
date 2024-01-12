//! # DID Web Implementation
//! <https://w3c-ccg.github.io/did-method-web/>

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

/// DID Web registrar. Implementation of the applicable DID operations, other than Read.
pub mod registrar;

/// DID Web resolver. Implementation of the DID Read operation.
pub mod resolver;

/// Main types for the DID Web registrar and resolver.
pub mod web;
