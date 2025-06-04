//! # DID Operations and Resolver
//!
//! This crate provides common utilities for the Credibil project and is not
//! intended to be used directly.
//!
//! The crate provides a DID Resolver trait and a set of default implementations
//! for resolving DIDs.
//!
//! See [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) fpr more.

pub mod core;
pub mod did;
pub mod proof;
mod provider;

pub use credibil_jose as jose;
pub use credibil_se as se;
pub use provider::*;
