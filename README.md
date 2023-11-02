# ZK EigenTrust - Deprecated

**Notice: This project is no longer being maintained as of November 2023.**

[![MIT licensed][mit-badge]][mit-url]
[![Build Status][actions-badge]][actions-url]

[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/eigen-trust/protocol/blob/master/LICENSE
[actions-badge]: https://github.com/eigen-trust/protocol/actions/workflows/test.yml/badge.svg
[actions-url]: https://github.com/eigen-trust/protocol/actions?query=branch%3Amaster

A Rust and Halo2-based library designed to manage trust in distributed networks with zero-knowledge proofs, guided by the framework established in the original [EigenTrust paper](https://nlp.stanford.edu/pubs/eigentrust.pdf). Its primary characteristics are:

- **Self-policing**: The shared ethics of the user population is defined and enforced by the peers themselves and not by some central authority.

- **Minimal**: computation, infrastructure, storage, and message complexity are reduced to a minimum.

- **Incorruptible**: Reputation should be obtained by consistent good behavior through several transactions. This is enforced for all users, so no one can cheat the system and obtain a higher reputation. It is also resistant to malicious collectives.

## Deprecation Notice

Effective November 2023, this project has been deprecated and is no longer under active development.

We invite the community to fork and maintain their own versions of this codebase. Should you choose to do so, we remind you to comply with the terms outlined in the [license](LICENSE).

## Structure

The project is organized in three crates:

- [eigentrust](eigentrust): This is the core library crate. It provides the `Client` struct for interfacing with the EigenTrust algorithm's circuits and includes additional modules to extend its functionality and facilitate integration.

- [eigentrust-cli](eigentrust-cli): This crate offers a command-line interface application that serves as a practical example of using the library. It supports operations such as deploying smart contracts, submitting attestations, calculating global trust scores, and generating and verifying zero-knowledge proofs.

- [eigentrust-zk](eigentrust-zk): Dedicated to the zero-knowledge components of the protocol, this crate encompasses the necessary Chips, Chipsets, and Circuits that pertain to the EigenTrust protocol implementation.

For a more in-depth understanding of the project's architecture and functionality, please refer to the documentation in the [docs](docs) directory.

There's also a [scripts](scripts) directory containing scripts for building documentation, running tests across the workspace, and compiling the entire project.

### License

Licensed under the MIT License - see the [LICENSE](LICENSE) file for details or visit [opensource.org](http://opensource.org/licenses/MIT).

### Acknowledgements

- Ethereum Foundation and Privacy & Scaling Explorations team.
- All contributors to this repository.
