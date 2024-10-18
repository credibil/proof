# Decentralized Identifier (DID) Tools

This crate provides a set of tools and utilities for working with a subset of 
[Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/).

## Supported Methods

The crate supports the following DID methods (used by `vercre-vc` and `vercre-dwn`):

- [did:key](https://w3c-ccg.github.io/did-method-key/)
- [did:web](https://w3c-ccg.github.io/did-method-web/)
- [did:jwk](https://github.com/quartzjer/did-jwk/blob/main/spec.md/)

with plans to support [did:dht](https://did-dht.com/) in the near future.

## Usage

The library supports basic DID resolution and document creation. It does not (yet) support
publishing a `did:web` document to a web server.

## Additional

[![Docs.rs Status](https://docs.rs/oxide-auth/badge.svg)](https://docs.rs/oxide-auth/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE-MIT)
[![License](https://img.shields.io/badge/license-Apache-blue.svg)](./LICENSE-APACHE)

More information about [contributing][CONTRIBUTING]. Please respect that I
maintain this on my own currently and have limited time. I appreciate
suggestions but sometimes the associate workload can seem daunting. That means
that simplifications to the workflow are also *highly* appreciated.

Licensed under either of

- MIT license ([LICENSE-MIT] or <http://opensource.org/licenses/MIT>)
- Apache License, Version 2.0 ([LICENSE-APACHE] or <http://www.apache.org/licenses/LICENSE-2.0>)
at your option.

The license applies to all parts of the source code, its documentation and
supplementary files unless otherwise indicated. It does NOT apply to the
replicated full-text copies of referenced RFCs which were included for the sake
of completion. These are distributed as permitted by [IETF Trust License
4–Section 3.c.i][IETF4].

<!-- [CHANGES]: CHANGELOG.md -->
[CONTRIBUTING]: ./CONTRIBUTING.md
[LICENSE-MIT]: ./LICENSE-MIT
[LICENSE-APACHE]: ./LICENSE-APACHE
[IETF4]: https://trustee.ietf.org/license-info/IETF-TLP-4.htm
