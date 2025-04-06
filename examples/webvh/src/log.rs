
use std::{collections::HashMap, sync::{Arc, Mutex}};

use credibil_did::webvh::DidLog;

#[derive(Clone, Debug)]
pub struct Log {
    entries: Arc<Mutex<HashMap<String, DidLog>>>
}

impl Log {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new()))
        }
    }

    pub fn add_log(&self, id: impl ToString, entry: DidLog) -> anyhow::Result<()> {
        let mut entries = self.entries.lock().map_err(|_| {
            anyhow::anyhow!("failed to lock entries mutex")
        })?;
        entries.insert(id.to_string(), entry);
        Ok(())
    }

    // pub fn get_log(&self) -> anyhow::Result<HashMap<String, DidLog>> {
    //     let entries = self.entries.lock().map_err(|_| {
    //         anyhow::anyhow!("failed to lock entries mutex")
    //     })?;
    //     Ok(entries.clone())
    // }
}
