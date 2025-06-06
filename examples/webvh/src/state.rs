//! Application state
use std::sync::Arc;

use kms::KeyringExt as Keyring;
use tokio::sync::Mutex;

use crate::log::Log;

#[derive(Clone)]
pub struct AppState {
    pub keyring: Arc<Mutex<Keyring>>,
    pub log: Arc<Mutex<Log>>,
}

impl AppState {
    #[must_use]
    pub async fn new() -> Self {
        let keyring = Keyring::new("issuer").await.expect("keyring creation");
        Self {
            keyring: Arc::new(Mutex::new(keyring)),
            log: Arc::new(Mutex::new(Log::new())),
        }
    }
}
