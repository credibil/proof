# `did:webvh` DID Method Example

This is a simple example of implementing a `did:webvh` DID method service using [Credibil's](https://credibil.io) DID library, the `credibil-did` crate for Rust.

It is a minimal implementation using very simple DID documents and runs as a web service.

## Getting Started

The example exists in a Cargo workspace so clone the whole [`credibil-did` repository](https://github.com/credibil/did) and start the self-contained web service from the repository root:

```shell
cargo run -p webvh
```

Then using curl or Postman you can explore creating, updating, resolving and deactivating a DID document:

### Create

```shell
curl --location 'http://localhost:8080/create' \
--header 'Content-Type: application/json' \
--data '{}'
```
### Read JSON Log

The read endpoint will `GET` the JSON log file (`did.jsonl`). You can call this after the other operations to see their effect.

```shell
curl --location 'http://localhost:8080/.well-known/did.jsonl'
```

Note that for convenience, the returned result for this example is a JSON document with entries as array members. In a real application the output should be a slighly more compact JSONL format.

### Update

The update endpoint will rotate keys and add another verification method to the DID document.
