# ZK Eigen Trust
A library for managing trust in a distributed network with zero-knowledge features.

## Main characteristics:
**Self-policing** - the shared ethics of the user population is defined and enforced by the peers themselves and not by some central authority.

**Minimal** - computation, infrastructure, storage, and message complexity are reduced to a minimum.

**Incorruptible** - Reputation should be obtained by consistent good behavior through several transactions. This is enforced for all users, so no one can cheat the system and obtain a higher reputation. It is also resistant to malicious collectives.

## Implementation
The library is implemented according to the original [Eigen Trust paper](http://ilpubs.stanford.edu:8090/562/1/2002-56.pdf). It is developed under the Ethereum Foundation grant.

## Usage
To build the project:
```bash
./scripts/build.sh
```

To build the project for the wasm target:
```bash
./scripts/build-wasm.sh
```

To run the tests (including the integration tests):
```bash
./scripts/test.sh
```

To build the documentation:
```bash
./scripts/build-docs.sh

# Open the documentation in the browser
cargo test --no-deps --open
```