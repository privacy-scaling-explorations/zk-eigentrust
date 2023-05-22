//! # Eigen Trust
//!
//! A library for managing trust in a distributed network with zero-knowledge
//! features.
//!
//! ## Main characteristics:
//! **Self-policing** - the shared ethics of the user population is defined and
//! enforced by the peers themselves and not by some central authority.
//!
//! **Minimal** - computation, infrastructure, storage, and message complexity
//! are reduced to a minimum.
//!
//! **Incorruptible** - Reputation should be obtained by consistent good
//! behavior through several transactions. This is enforced for all users, so no
//! one can cheat the system and obtain a higher reputation. It is also
//! resistant to malicious collectives.
//!
//! ## Implementation
//! The library is implemented according to the original [Eigen Trust paper](http://ilpubs.stanford.edu:8090/562/1/2002-56.pdf).
//! It is developed under the Ethereum Foundation grant.

pub mod att_station;
pub mod attestation;
pub mod error;
pub mod eth;
pub mod utils;

use att_station::{AttestationCreatedFilter, AttestationStation};
use attestation::{get_contract_attestation_data, Attestation, AttestationPayload};
use eigen_trust_circuit::dynamic_sets::native::SignedAttestation;
use error::EigenError;
use eth::ecdsa_secret_from_mnemonic;
use ethers::{
	abi::{Address, RawLog},
	contract::EthEvent,
	prelude::EthDisplay,
	providers::Middleware,
	signers::{LocalWallet, Signer},
	types::{Filter, H256},
};
use ethers::{
	middleware::SignerMiddleware,
	providers::{Http, Provider},
	signers::{coins_bip39::English, MnemonicBuilder},
};
use secp256k1::{ecdsa::RecoverableSignature, Message, SecretKey, SECP256K1};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Max amount of participants
const MAX_NEIGHBOURS: usize = 2;
/// Number of iterations to run the eigen trust algorithm
const NUM_ITERATIONS: usize = 10;
/// Initial score for each participant before the algorithms is run
const INITIAL_SCORE: u128 = 1000;

#[derive(Serialize, Deserialize, Debug, EthDisplay, Clone)]
pub struct ClientConfig {
	pub as_address: String,
	pub et_verifier_wrapper_address: String,
	pub mnemonic: String,
	pub node_url: String,
}

/// Signer middleware type alias
pub type SignerMiddlewareArc = Arc<SignerMiddleware<Provider<Http>, LocalWallet>>;

/// Client
pub struct Client {
	client: SignerMiddlewareArc,
	config: ClientConfig,
}

impl Client {
	/// Create a new client
	pub fn new(config: ClientConfig) -> Self {
		let client = setup_client(&config.mnemonic, &config.node_url);
		Self { client, config }
	}

	/// Submit an attestation to the attestation station
	pub async fn attest(&self, attestation: Attestation) -> Result<(), EigenError> {
		let ctx = SECP256K1;
		let secret_keys: Vec<SecretKey> =
			ecdsa_secret_from_mnemonic(&self.config.mnemonic, 1).unwrap();

		// Get AttestationFr
		let attestation_fr = attestation.to_attestation_fr();

		// Format for signature
		let att_hash = attestation_fr.hash();

		// Sign attestation
		let signature: RecoverableSignature = ctx.sign_ecdsa_recoverable(
			&Message::from_slice(att_hash.to_bytes().as_slice()).unwrap(),
			&secret_keys[0],
		);

		let signed_attestation = SignedAttestation::new(attestation_fr, signature);

		let as_address_res = self.config.as_address.parse::<Address>();
		let as_address = as_address_res.map_err(|_| EigenError::ParseError)?;
		let as_contract = AttestationStation::new(as_address, self.client.clone());

		let tx_call = as_contract.attest(vec![
			get_contract_attestation_data(&signed_attestation).unwrap()
		]);
		let tx_res = tx_call.send();
		let tx = tx_res.await.map_err(|_| EigenError::TransactionError)?;
		let res = tx.await.map_err(|_| EigenError::TransactionError)?;

		if let Some(receipt) = res {
			println!("Transaction status: {:?}", receipt.status);
		}

		Ok(())
	}

	/// Calculate proofs
	pub async fn calculate_proofs(&mut self) -> Result<(), EigenError> {
		// TODO: Implement
		Ok(())
	}

	/// Get the attestations from the contract
	pub async fn get_attestations(&self) -> Result<Vec<Attestation>, EigenError> {
		let filter = Filter::new()
			.address(self.config.as_address.parse::<Address>().unwrap())
			.event("AttestationCreated(address,address,bytes32,bytes)")
			.topic1(Vec::<H256>::new())
			.topic2(Vec::<H256>::new())
			.from_block(0);
		let logs = &self.client.get_logs(&filter).await.unwrap();
		let mut attestations = Vec::new();

		println!("Indexed attestations: {}", logs.iter().len());

		for log in logs.iter() {
			let raw_log = RawLog::from((log.topics.clone(), log.data.to_vec()));
			let att_created = AttestationCreatedFilter::decode_log(&raw_log).unwrap();
			let att_data =
				AttestationPayload::from_bytes(att_created.val.to_vec()).expect("Failed to decode");

			let att = Attestation::new(
				att_created.about.into(),
				att_created.key.into(),
				att_data.get_value(),
				Some(att_data.get_message().into()),
			);

			attestations.push(att);
		}

		Ok(attestations)
	}

	/// Verifies last generated proof
	pub async fn verify(&self) -> Result<(), EigenError> {
		// TODO: Verify proof
		Ok(())
	}
}

/// Setup Client middleware
fn setup_client(mnemonic_phrase: &str, node_url: &str) -> SignerMiddlewareArc {
	let provider = Provider::<Http>::try_from(node_url).unwrap();
	let wallet = MnemonicBuilder::<English>::default().phrase(mnemonic_phrase).build().unwrap();
	let client = SignerMiddleware::new(provider, wallet.with_chain_id(31337u64));

	Arc::new(client)
}

#[cfg(test)]
mod lib_tests {
	use crate::{
		attestation::Attestation,
		eth::{deploy_as, deploy_verifier},
		Client, ClientConfig,
	};
	use eigen_trust_circuit::utils::read_bytes_data;
	use ethers::abi::Address;
	use ethers::{types::U256, utils::Anvil};

	#[tokio::test]
	async fn test_attest() {
		let anvil = Anvil::new().spawn();
		let node_url = anvil.endpoint();
		let mnemonic = "test test test test test test test test test test test junk".to_string();

		let as_address = deploy_as(&mnemonic, &node_url).await.unwrap();
		let et_verifier_address =
			deploy_verifier(&mnemonic, &node_url, read_bytes_data("et_verifier")).await.unwrap();

		let config = ClientConfig {
			as_address: format!("{:?}", as_address),
			et_verifier_wrapper_address: format!("{:?}", et_verifier_address),
			mnemonic: mnemonic.clone(),
			node_url,
		};

		let attestation = Attestation::new(Address::default(), U256::default(), 1, None);

		assert!(Client::new(config).attest(attestation).await.is_ok());

		drop(anvil);
	}
}
