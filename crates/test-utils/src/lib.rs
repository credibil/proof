//! Key management

mod docstore;
mod vault;

pub use crate::docstore::DocStore;
pub use crate::vault::KeyVault as Vault;
