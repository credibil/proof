//! # `KeyRing` and `Signer` implementations for Azure Key Vault

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

mod auth;
mod client;
mod error;
mod key_bundle;
mod keyring;
mod signer;

pub use client::KeyVault;
pub use keyring::AzureKeyRing;
pub use signer::AzureSigner;
