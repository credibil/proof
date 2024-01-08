//! `KeyRing` and `Signer` implementations for keys that are not stored anywhere.

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

mod keyring;
mod signer;

pub use keyring::EphemeralKeyRing;
pub use signer::EphemeralSigner;
