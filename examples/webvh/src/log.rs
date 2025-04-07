
use std::collections::HashMap;

use credibil_did::webvh::DidLog;

#[derive(Clone, Debug)]
pub struct Log {
    entries: HashMap<String, DidLog>
}

impl Log {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new()
        }
    }

    pub fn add_log(&mut self, id: impl ToString, entry: DidLog) -> anyhow::Result<()> {
        self.entries.insert(id.to_string(), entry);
        Ok(())
    }

    // pub fn get_log(&self) -> anyhow::Result<HashMap<String, DidLog>> {
    //     let entries = self.entries.lock().map_err(|_| {
    //         anyhow::anyhow!("failed to lock entries mutex")
    //     })?;
    //     Ok(entries.clone())
    // }
}
