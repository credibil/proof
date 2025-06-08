//! # DID Operations and Resolver
//!
//! This crate provides common utilities for the Credibil project and is not
//! intended to be used directly.
//!
//! The crate provides a DID Resolver trait and a set of default implementations
//! for resolving DIDs.
//!
//! See [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) fpr more.

mod document;
pub mod key;
mod resolve;
mod service;
mod url;
mod verification;
pub mod web;
pub mod webvh;

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use anyhow::anyhow;

pub use self::document::*;
pub use self::resolve::{Resource, deref_url, dereference, document_resource};
pub use self::service::*;
pub use self::url::{QueryParams, Url};
pub use self::verification::*;

/// DID methods supported by this crate.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `did:key`
    #[default]
    Key,

    /// `did:web`
    Web,

    /// `did:webvh`
    WebVh,
}

impl FromStr for Method {
    type Err = anyhow::Error;

    /// Parse a string into a [`Method`].
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not a valid method.
    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s {
            "key" => Ok(Self::Key),
            "web" => Ok(Self::Web),
            "webvh" => Ok(Self::WebVh),
            _ => Err(anyhow!("method not supported: {s}")),
        }
    }
}

impl Display for Method {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Key => write!(f, "key"),
            Self::Web => write!(f, "web"),
            Self::WebVh => write!(f, "webvh"),
        }
    }
}
