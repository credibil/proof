//! Application state
use std::sync::Arc;

use kms::Keyring;
use tokio::sync::Mutex;

use crate::log::Log;

#[derive(Clone, Debug)]
pub struct AppState {
    pub keyring: Arc<Mutex<Keyring>>,
    pub log: Arc<Mutex<Log>>,
}

impl AppState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            keyring: Arc::new(Mutex::new(Keyring::new())),
            log: Arc::new(Mutex::new(Log::new())),
        }
    }
}
