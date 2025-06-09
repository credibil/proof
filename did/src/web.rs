//! # DID Web
//!
//! The `did:web` method uses a web domain's reputation to confer trust.
//!
//! See:
//!
//! - <https://w3c-ccg.github.io/did-method-web>
//! - <https://w3c.github.io/did-resolution>

mod create;
mod resolve;
mod url;

pub use self::create::*;
pub use self::resolve::*;
pub use self::url::*;

