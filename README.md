# ZK Eigen Trust

[![MIT licensed][mit-badge]][mit-url]
[![Build Status][actions-badge]][actions-url]

[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/eigen-trust/protocol/blob/master/LICENSE
[actions-badge]: https://github.com/eigen-trust/protocol/actions/workflows/test.yml/badge.svg
[actions-url]: https://github.com/eigen-trust/protocol/actions?query=branch%3Amaster

A library for managing trust in a distributed network with zero-knowledge features.

## Main characteristics:

**Self-policing** - the shared ethics of the user population is defined and enforced by the peers themselves and not by some central authority.

**Minimal** - computation, infrastructure, storage, and message complexity are reduced to a minimum.

**Incorruptible** - Reputation should be obtained by consistent good behavior through several transactions. This is enforced for all users, so no one can cheat the system and obtain a higher reputation. It is also resistant to malicious collectives.

## Development Guidelines

The following document explains the development process and our values:

[Development Process](https://hackmd.io/MzCV5EGyTo-aNIRUV0PnUQ)

## Usage

To build the project:

```bash
./scripts/build.sh
```

To build the documentation:

```bash
./scripts/build-docs.sh

# Open the documentation in the browser
cargo doc --no-deps --open
```

## License

This library is licensed under the following license:

- MIT license ([LICENSE](LICENSE) or [opensource.org license link](http://opensource.org/licenses/MIT))

## Acknowledgements

This project is developed under the Ethereum Foundation grant.

The library is implemented according to the original [Eigen Trust paper](https://web.archive.org/web/20230219174826/http://ilpubs.stanford.edu:8090/562/1/2002-56.pdf).
