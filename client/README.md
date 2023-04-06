# EigenTrust Protocol

This crate is an implementation of the EigenTrust Protocol. It's intended use is either as a library for other implementations or as a standalone implementation.

## Requirements

- Rust: To install, follow the instructions found [here](https://www.rust-lang.org/tools/install).
- Solidity Compiler: To install, follow the instructions found [here](https://docs.soliditylang.org/en/v0.8.9/installing-solidity.html).
- Anvil: CLI tool for running a local EVM blockchain. Follow these steps to install Anvil from source:

```bash
git clone https://github.com/foundry-rs/foundry
cd foundry
cargo install --path ./anvil --bins --locked --force
```

## Getting Started

If running the project locally, the first step is to spin up our local EVM blockchain with Anvil. This is achieved by running the `anvil` command:

```bash
anvil
```

This implementation has two main components, a client and a server. The first thing we want to run is the server, so we can calculate the global reputation scores from the attestations.

```bash
cd ./server
cargo run --release
```

The last step is running the client. The client has a command line interface implemented with [clap.rs](http://clap.rs/) that allows us to, among other things, deploy contracts and submit attestations.

```bash
cd ../client
cargo run --release -- compile-contracts
cargo run --release -- deploy-contracts
```

We can now submit attestations. The attestation data is stored in the `client-config.json` file in the `data` directory. We will explore more about this in the Configuration section.

```bash
cargo run --release -- attest
```

And we’re running! If everything went well, our server should be calculating the global scores for our reputation system.

## CLI

The client's command-line interface was built using [clap.rs](http://clap.rs/). It provides the following functions:

- `attest`: Takes `ops` from the `client-config.json` file, signs it using `secret_key`, and submits it to the AttestationStation smart contract.
- `compile-contracts`: Compiles all the `.sol` and `.yul` contracts available in the `data` folder. For `.sol` contracts, it generates an ABI JSON file and a Rust binding file. For `.yul` smart contracts, it compiles Yul code into binary.
- `deploy-contracts`: Deploys all the contracts.
- `show`: Displays the `client-config.json` file.
- `update`: Updates the specified field in `client-config.json`. The argument must be passed with `--subcommand "new-value"`. The available subcommands are:
    - `name`
    - `score`
    - `sk`
    - `as_address`
    - `mnemonic`
    - `node_url`
- `verify`: Fetches the proof from the server on `server_url` and submits the proof to ET Verifier on `et_verifier_wrapper_address`.

## Configuration

### Client

The client configuration is stored in `data/client-config.json`, which specifies the following parameters:

- `ops`: Contains the peer scores for the entire group, currently fixed at five members.
- `secret_key`: An EdDSA secret key, is used to manage the EigenTrust sets.
- `as_address`: The address of the AttestationStation contract.
- `et_verifier_wrapper_address`: A verifier smart contract for the EigenTrust global scores proof.
- `mnemonic`: Mnemonic for an Ethereum wallet.
- `ethereum_node_url`: The URL for the Ethereum node.
- `server_url`: The URL for the running server.

### Server

The server was built using [hyper.rs](http://hyper.rs/). You can find the configuration file at `data/protocol-config.json`, where you can specify the following:

- `epoch_interval`: Interval at which proofs are calculated
- `endpoint`: Socket that listens for connections to the server
- `ethereum_node_url`: URL of the Ethereum node we are connecting to. This defaults to `127.0.0.1:8545` to run with a local `anvil` EVM blockchain.
- `as_contract_address`: Address of the AttestationStation smart contract from which events are being fetched.
