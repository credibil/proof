
use crate::keyring::Keyring;
use crate::log::Log;

#[derive(Clone, Debug)]
pub struct AppState {
    pub keyring: Keyring,
    pub log: Log,
}

impl AppState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            keyring: Keyring::new(),
            log: Log::new(),
        }
    }
}
