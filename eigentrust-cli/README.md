# ZK EigenTrust CLI

[![MIT licensed][mit-badge]][mit-url]
[![Build Status][actions-badge]][actions-url]

[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/eigen-trust/protocol/blob/master/LICENSE
[actions-badge]: https://github.com/eigen-trust/protocol/actions/workflows/test.yml/badge.svg
[actions-url]: https://github.com/eigen-trust/protocol/actions?query=branch%3Amaster

This crate provides a CLI interface to use the `eigentrust` library. It allows you to deploy the smart contracts, submit attestations, calculate the global scores and generate the zk proofs.

## Requirements

- Rust: To install, follow the instructions found [here](https://www.rust-lang.org/tools/install).
- Solidity Compiler: To install, follow the instructions found [here](https://docs.soliditylang.org/en/v0.8.9/installing-solidity.html), or use the [Solidity Compiler Version Manager](https://github.com/alloy-rs/svm-rs) (recommended):

```bash
cargo install svm-rs
svm install 0.8.17
```

- Anvil: CLI tool for running a local EVM blockchain. Follow these steps to install Anvil from source:

```bash
git clone https://github.com/foundry-rs/foundry
cd foundry
cargo install --path ./anvil --bins --locked --force
```

## Getting Started

If you want to use a local EVM blockchain, the first step is to spin up Anvil by running the `anvil` command:

```bash
anvil
```

Otherwise you should configure the `node_url` data field of the `config.json` file in the `assets` folder to point to the correct Ethereum node. There's more about this in the configuration section.

Open a new terminal to use the CLI. Let's build the release version of the crate so we can run it from the `target` directory:

```bash
cargo build --release
```

Once the project is built, we need to deploy the AttestationStation smart contract to the blockchain. This is done by running the `deploy` command:

```bash
./target/release/eigentrust-cli deploy
```

The next step is submitting an attestation to a peer in the network. Attestations allow us to give a score to a peer and store that in the blockchain. This is done by running the `attest` command:

```bash
./target/release/eigentrust-cli attest --to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --score 5
```

With two peers and one score we can now run the eigentrust algorithm and calculate the global scores, but first we need to generate some important parameters. We'll start generating the KZG public verifier parameters.

**This command could take some time to complete depending on your hardware ⏳**

```bash
./target/release/eigentrust-cli kzg-params
```

Once we have them, it's possible to create a proving key:

```bash
./target/release/eigentrust-cli et-proving-key
```

Now it's time to calculate the global scores and generate a proof that they have been correctly calculated:

```bash
./target/release/eigentrust-cli et-proof
```

Finally, we can verify the generated proof:

```bash
./target/release/eigentrust-cli et-verify
```

And that's it! Keep in mind that if you'd like to keep attesting and generating proofs, you don't need to generate the KZG parameters and the verifying key again.

## CLI

The command-line interface was built using [clap.rs](http://clap.rs/). There is a command description in the help menu, which can be opened passing `-h`. It also provides the following command options:

- `attest`: Submits an attestation. Takes the following options:
  - `--to`: Specify the attested address.
  - `--score`: Specify the given score (between 0 and 255).
  - `--message`: Specify an optional 32-byte message in hexadecimal format.
- `attestations`: Retrieves and stores all attestations.
- `bandada`: Used to manage Semaphore groups using the Bandada API. It is designed to either add participants to a group or remove them from it. Before executing this command, you should run the `scores` command to ensure having participants' scores, and to setup the `band-id` and `band-th` in the configuration . Please note that when adding a participant, the command checks if their score is above the defined bandada group threshold, and only then proceeds with the addition. It requires the following options:
  - `--action (add | remove)`: Defines the action to perform. You can choose to `add` a new member to a group or `remove` an existing member from it.
  - `--ic`: Provides the identity commitment of the participant you intend to add or remove from the group.
  - `--addr`: Specifies the participant's Ethereum address.
- `deploy`: Deploys the AttestationStation contract.
- `et-proof`: Runs the EigenTrust algorithm to calculate the global scores and stores the generated proof.
- `et-proving-key`: Generates the EigenTrust circuit proving keys.
- `et-verify`: Verifies the stored generated proof for the EigenTrust algorithm.
- `kzg-params`: Generates the KZG parameters.
- `local-scores`: Uses locally stored attestation to calculate the global scores and stores them in the `scores.csv` file within the `assets` folder.
- `scores`: Retrieve attestations and calculates the global scores and stores them in the `scores.csv` file within the `assets` folder.
- `show`: Displays the `config.json` file.
- `update`: Updates the specified field in `config.json`. Takes the following options:

  - `--as-address`: Updates the address of the AttestationStation contract.
  - `--domain`: Updates the domain identifier.
  - `--band-id`: Updates the bandada group id.
  - `--band-th`: Updates the bandada group score threshold.
  - `--band-url`: Updates the bandada API endpoint.
  - `--chain-id`: Updates the network chain id.
  - `--node`: Updates the Ethereum node URL.

### Example of `update` command

```bash
./target/release/eigentrust-cli update --node http://localhost:8545
```

### Example of `attest` command

```bash
./target/release/eigentrust-cli attest --to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --score 5 --message 0x473fe1d0de78c8f334d059013d902c13c8b53eb0f669caa9cad677ce1a601167
```

### Example of `bandada` command

```bash
./target/release/eigentrust-cli scores # Can be skipped for testing, a scores.csv file is provided.
./target/release/eigentrust-cli update --band-id 51629751621128677209874422363557 --band-th 500
./target/release/eigentrust-cli bandada --action add --ic 82918723982 --addr 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
```

## Configuration

The configuration file is stored in `eigentrust-cli/assets/config.json`. You may need to update these parameters if, for example, the smart contracts are redeployed to new addresses or if you want to connect to a different Ethereum node. You can modify the following parameters:

- `as_address`: AttestationStation smart contract address. This is the contract that will receive the attestations.
- `mnemonic`: Ethereum wallet mnemonic phrase.
- `band_id`: Bandada group id.
- `band_th`: Bandada group score threshold. This is the minimum score required to be added to a bandada group.
- `band_url`: Bandada API endpoint.
- `chain_id`: Network chain id. The default is `31337` to work with a local network.
- `node_url`: URL of the Ethereum node we are connecting to. The default is `http://localhost:8545` to work with a local network.

These parameters can also be modified using the `update` CLI command.

## Environment Configuration

You can customize some settings through environment variables:

- `MNEMONIC`: Your Ethereum wallet's mnemonic phrase.
- `BANDADA_API_KEY`: The Bandada group API key.
- `LOG_LEVEL`: The logging level. Available options are `error | warn | info | debug | trace`. Default is `info`.

We've provided a template for these variables in a file named `.env.origin`. You can create a copy of this file and rename it to `.env`:

```bash
cp .env.origin .env
```

Next, edit the `.env` file and replace the placeholder values with your actual ones:

```bash
MNEMONIC="your mnemonic phrase"
BANDADA_API_KEY="your bandada group api key"
LOG_LEVEL="info"
```

Feel free to only specify variables you want to change from their defaults.
