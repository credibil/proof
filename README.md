# Decentralized Identifiers

This crate provides a set of tools and utilities for working with [Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/). It is intended to be a general purpose library for working with DIDs, and is not specific to any particular DID method. However, some DID methods have been implemented and can be included by using the relevant feature flag.

## Key Management, Signing and Verification

Some support is provided for key management, including creating and deprecating keys and handling key versions. Guided by DID ION, keys can be issued for different purposes. Message signing and signature verification is included for a limited set of signing algorithms but you are free to configure and use whatever algorithm you need. This crate is intended to be a minimal set of tools to support the DID methods implemented in this crate. It is not intended to be a general purpose cryptographic library and instead imports well-supported and recognised crates for this. While we have taken as much care as possible, feedback on strengthening the security of this crate is welcome.

The `Keyring` trait is the specification for key management and the `Signer` trait for message signing. The `Signer` trait also specifies a `verify` method that allows using the underlying Keyring for verification but downstream clients could use any verification function that understands the cryptographic algorithm used to sign the message and has access to the verification key.

## DID Method Features

### DID-ION

`features = ["did-ion"]`

The genesis of this crate is a Rust port of the JavaScript [ION Tools](https://github.com/decentralized-identity/ion-tools) library. It includes a similar set of tools and utilities intended to make working with ION easier for Rust developers.

### DID-Web

`features = ["did-web"]`

TODO: Support for DID-Web is planned, but not yet implemented.

### DID-Key

`features = ["did-key"]`

TODO: Support for DID-Key is planned, but not yet implemented.

## Keyring and Signer Features

The following specific Keyring and Signer implementations have been implemented and can be included by using the relevant feature flag.

### Azure Key Vault with Secp256k1 Keys

`features = ["azure-kv"]`

## Specification

This repository attempts to conform to the W3C recommendation for [Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/). Feedback on non-compliance is welcome.

## Additional

<!-- [![Crates.io Status](https://img.shields.io/crates/v/oxide-auth.svg)](https://crates.io/crates/oxide-auth) -->
[![Docs.rs Status](https://docs.rs/oxide-auth/badge.svg)](https://docs.rs/oxide-auth/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE-MIT)
[![License](https://img.shields.io/badge/license-Apache-blue.svg)](./LICENSE-APACHE)
<!-- [![CI Status](https://api.cirrus-ci.com/github/HeroicKatora/oxide-auth.svg)](https://cirrus-ci.com/github/HeroicKatora/oxide-auth) -->

A more or less comprehensive list of changes is contained in the
[changelog][CHANGES]. Sometimes less as larger releases and reworks profit from
a rough overview of the changes more than a cumulative list of detailed
features.

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
