//! # DID JWK Implementation
//! <https://github.com/quartzjer/did-jwk/blob/main/spec.md>

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

/// Main types for the DID JWK registrar and resolver.
pub mod jwk;
/// DID JWK registrar. Implementation of the applicable DID operations, other than Read.
pub mod registrar;
/// DID JWK resolver. Implementation of the DID Read operation.
pub mod resolver;
