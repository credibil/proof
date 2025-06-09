//! # Docstore

use std::sync::LazyLock;

use anyhow::Result;
use dashmap::DashMap;

/// `Datastore` is used by implementers to provide data storage
/// capability.
pub trait Docstore: Send + Sync {
    /// Store a data item in the underlying item store.
    fn put(
        &self, owner: &str, partition: &str, key: &str, data: &[u8],
    ) -> impl Future<Output = Result<()>> + Send;

    /// Fetches a single item from the underlying store, returning `None` if
    /// no match was found.
    fn get(
        &self, owner: &str, partition: &str, key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send;

    // /// Delete the specified data item.
    // fn delete(
    //     &self, owner: &str, partition: &str, key: &str,
    // ) -> impl Future<Output = Result<()>> + Send;

    // /// Fetches all matching items from the underlying store.
    // fn get_all(
    //     &self, owner: &str, partition: &str,
    // ) -> impl Future<Output = Result<Vec<(String, Vec<u8>)>>> + Send;
}

static STORE: LazyLock<DashMap<String, Vec<u8>>> = LazyLock::new(DashMap::new);

#[derive(Clone, Debug)]
pub struct Store;

impl Docstore for Store {
    async fn put(&self, owner: &str, partition: &str, key: &str, data: &[u8]) -> Result<()> {
        let key = format!("{owner}-{partition}-{key}");
        STORE.insert(key, data.to_vec());
        Ok(())
    }

    async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let key = format!("{owner}-{partition}-{key}");
        let Some(bytes) = STORE.get(&key) else {
            return Ok(None);
        };
        Ok(Some(bytes.to_vec()))
    }

    // async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
    //     let key = format!("{owner}-{partition}-{key}");
    //     STORE.remove(&key);
    //     Ok(())
    // }

    // async fn get_all(&self, owner: &str, partition: &str) -> Result<Vec<(String, Vec<u8>)>> {
    //     let all = STORE
    //         .iter()
    //         .filter(move |r| r.key().starts_with(&format!("{owner}-{partition}-")))
    //         .map(|r| (r.key().to_string(), r.value().clone()))
    //         .collect::<Vec<_>>();
    //     Ok(all)
    // }
}
