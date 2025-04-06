
use crate::keyring::Keyring;

#[derive(Clone, Debug)]
pub struct AppState {
    pub keyring: Keyring,
    // pub log: Arc<Mutex<HashMap<String, Vec<DidLog>>>>,
}

impl AppState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            keyring: Keyring::new(),
            // log: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
