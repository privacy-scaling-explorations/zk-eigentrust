//! # Eigen Trust
//!
//! A library for managing trust in a distributed network with zero-knowledge
//! features.
//!
//! ## Main characteristics:
//!
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
//!
//! The library is implemented according to the original [Eigen Trust paper](http://ilpubs.stanford.edu:8090/562/1/2002-56.pdf).
//! It is developed under an Ethereum Foundation grant.

// Rustc
#![warn(trivial_casts)]
#![deny(
	absolute_paths_not_starting_with_crate, deprecated, future_incompatible, missing_docs,
	nonstandard_style, unreachable_code, unreachable_patterns
)]
#![forbid(unsafe_code)]
#![deny(
	// Complexity
 	clippy::unnecessary_cast,
	clippy::needless_question_mark,
	// Pedantic
 	clippy::cast_lossless,
 	clippy::cast_possible_wrap,
	// Perf
	clippy::redundant_clone,
	// Restriction
 	clippy::panic,
	// Style
 	clippy::let_and_return,
 	clippy::needless_borrow
)]

pub mod att_station;
pub mod attestation;
pub mod error;
pub mod eth;
pub mod storage;

use crate::attestation::address_from_signed_att;
use att_station::{AttestationCreatedFilter, AttestationStation};
use attestation::{att_data_from_signed_att, Attestation, AttestationPayload};
use dotenv::{dotenv, var};
use eigen_trust_circuit::{
	dynamic_sets::ecdsa_native::{EigenTrustSet, RationalScore, SignedAttestation},
	halo2::halo2curves::bn256::Fr as Scalar,
};
use error::EigenError;
use eth::{address_from_public_key, ecdsa_secret_from_mnemonic, scalar_from_address};
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
use std::{collections::BTreeSet, sync::Arc};

/// Max amount of participants.
const MAX_NEIGHBOURS: usize = 4;
/// Number of iterations to run the eigen trust algorithm.
const NUM_ITERATIONS: usize = 20;
/// Initial score for each participant before the algorithms is run.
const INITIAL_SCORE: u128 = 1000;
/// Number of limbs for representing big numbers in threshold checking.
const _NUM_LIMBS: usize = 2;
/// Number of digits of each limbs for threshold checking.
const _POWER_OF_TEN: usize = 72;

/// Client configuration settings.
#[derive(Serialize, Deserialize, Debug, EthDisplay, Clone)]
pub struct ClientConfig {
	/// AttestationStation contract address.
	pub as_address: String,
	/// Bandada group id.
	pub band_id: String,
	/// Bandada group threshold.
	pub band_th: String,
	/// Bandada API base URL.
	pub band_url: String,
	/// Attestation domain identifier.
	pub domain: String,
	/// Ethereum node URL.
	pub node_url: String,
	/// EigenTrustVerifier contract address.
	pub verifier_address: String,
}

/// Signer type alias.
pub type ClientSigner = SignerMiddleware<Provider<Http>, LocalWallet>;
/// Scores type alias.
pub type Score = (Address, Scalar, RationalScore);

/// Client struct.
pub struct Client {
	signer: Arc<ClientSigner>,
	config: ClientConfig,
	mnemonic: String,
}

impl Client {
	/// Creates a new Client instance.
	pub fn new(config: ClientConfig) -> Self {
		// Load environment config
		dotenv().ok();
		let mnemonic = var("MNEMONIC").unwrap_or_else(|_| {
			println!("MNEMONIC environment variable is not set. Using default.");
			"test test test test test test test test test test test junk".to_string()
		});

		// Setup provider
		let provider = Provider::<Http>::try_from(&config.node_url)
			.expect("Failed to create provider from config node url");

		// Setup wallet
		let wallet = MnemonicBuilder::<English>::default()
			.phrase(mnemonic.as_str())
			.build()
			.expect("Failed to build wallet with provided mnemonic");

		// Setup signer
		let signer: ClientSigner = SignerMiddleware::new(provider, wallet.with_chain_id(31337u64));

		// Arc for thread-safe sharing of signer
		let shared_signer = Arc::new(signer);

		Self { signer: shared_signer, config, mnemonic }
	}

	/// Submits an attestation to the attestation station.
	pub async fn attest(&self, attestation: Attestation) -> Result<(), EigenError> {
		let ctx = SECP256K1;
		let secret_keys: Vec<SecretKey> = ecdsa_secret_from_mnemonic(&self.mnemonic, 1).unwrap();

		// Get AttestationFr
		let attestation_fr = attestation.to_attestation_fr().unwrap();

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
		let as_contract = AttestationStation::new(as_address, self.signer.clone());

		// Verify signature is recoverable
		let recovered_pubkey = signed_attestation.recover_public_key().unwrap();
		let recovered_address = address_from_public_key(&recovered_pubkey).unwrap();
		assert!(recovered_address == self.signer.address());

		// Stored contract data
		let contract_data = att_data_from_signed_att(&signed_attestation).unwrap();

		let tx_call = as_contract.attest(vec![contract_data]);
		let tx_res = tx_call.send();
		let tx = tx_res.await.map_err(|_| EigenError::TransactionError)?;
		let res = tx.await.map_err(|_| EigenError::TransactionError)?;

		if let Some(receipt) = res {
			println!("Transaction status: {:?}", receipt.status);
		}

		Ok(())
	}

	/// Calculates the EigenTrust global scores.
	pub async fn calculate_scores(&self) -> Result<Vec<Score>, EigenError> {
		// Get attestations
		let attestations = self.get_attestations().await?;

		// Construct a set to hold unique participant addresses
		let mut participants_set = BTreeSet::<Address>::new();

		// Insert the attester and attested of each attestation into the set
		for (signed_att, att) in &attestations {
			participants_set.insert(att.about);
			participants_set.insert(address_from_signed_att(signed_att).unwrap());
		}

		// Create a vector of participants from the set
		let participants: Vec<Address> = participants_set.into_iter().collect();

		// Initialize attestation matrix
		let mut attestation_matrix: Vec<Vec<Option<SignedAttestation>>> =
			vec![vec![None; MAX_NEIGHBOURS]; MAX_NEIGHBOURS];

		// Populate the attestation matrix with the attestations data
		for (signed_att, att) in &attestations {
			let attester_address = address_from_signed_att(signed_att).unwrap();
			let attester_pos = participants.iter().position(|&r| r == attester_address).unwrap();
			let attested_pos = participants.iter().position(|&r| r == att.about).unwrap();

			attestation_matrix[attester_pos][attested_pos] = Some(signed_att.clone());
		}

		// Initialize EigenTrustSet
		let mut eigen_trust_set =
			EigenTrustSet::<MAX_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		// Add participants to set
		for participant in &participants {
			let participant_fr = scalar_from_address(participant).unwrap();
			eigen_trust_set.add_member(participant_fr);
		}

		// Update the set with the opinions of each participant
		for attestation_matrix_i in attestation_matrix.iter().take(participants.len()) {
			for j in 0..attestation_matrix_i.len() {
				if let Some(att) = attestation_matrix_i[j].clone() {
					let participant_pub_key = att.recover_public_key().unwrap();

					eigen_trust_set.update_op(participant_pub_key, attestation_matrix_i.clone());

					break;
				}
			}
		}

		// Calculate scores
		let scores_fr = eigen_trust_set.converge();
		let scores_rat = eigen_trust_set.converge_rational();

		// Check that the scores vectors are of equal length
		assert_eq!(
			scores_fr.len(),
			scores_rat.len(),
			"Scores vectors are not of equal length"
		);

		// Check that the scores vector is at least as long as the participants vector
		assert!(
			scores_fr.len() >= participants.len(),
			"There are more participants than scores"
		);

		// Group the scores with the participants
		let scores: Vec<Score> = participants
			.iter()
			.zip(scores_fr.iter())
			.zip(scores_rat.iter())
			.map(|((&participant, &score_fr), score_rat)| {
				(participant, score_fr, score_rat.clone())
			})
			.collect();

		Ok(scores)
	}

	/// Gets the attestations from the contract.
	pub async fn get_attestations(
		&self,
	) -> Result<Vec<(SignedAttestation, Attestation)>, EigenError> {
		let filter = Filter::new()
			.address(self.config.as_address.parse::<Address>().unwrap())
			.event("AttestationCreated(address,address,bytes32,bytes)")
			.topic1(Vec::<H256>::new())
			.topic2(Vec::<H256>::new())
			.from_block(0);
		let logs = &self.signer.get_logs(&filter).await.unwrap();
		let mut att_tuple: Vec<(SignedAttestation, Attestation)> = Vec::new();

		for log in logs.iter() {
			let raw_log = RawLog::from((log.topics.clone(), log.data.to_vec()));
			let att_created = AttestationCreatedFilter::decode_log(&raw_log).unwrap();
			let att_data =
				AttestationPayload::from_bytes(att_created.val.to_vec()).expect("Failed to decode");

			let att = Attestation::new(
				att_created.about,
				att_created.key.into(),
				att_data.get_value(),
				Some(att_data.get_message().into()),
			);

			let att_fr = att.to_attestation_fr().unwrap();

			let signature = att_data.get_signature();

			let signed_att = SignedAttestation::new(att_fr, signature);

			att_tuple.push((signed_att, att));
		}

		Ok(att_tuple)
	}

	/// Verifies last generated proof.
	pub async fn verify(&self) -> Result<(), EigenError> {
		// TODO: Verify proof
		Ok(())
	}

	/// Gets signer.
	pub fn get_signer(&self) -> Arc<ClientSigner> {
		self.signer.clone()
	}
}

#[cfg(test)]
mod lib_tests {
	use crate::{
		attestation::{Attestation, DOMAIN_PREFIX, DOMAIN_PREFIX_LEN},
		eth::{deploy_as, deploy_verifier},
		Client, ClientConfig,
	};
	use eigen_trust_circuit::utils::read_bytes_data;
	use ethers::{abi::Address, types::H256, utils::Anvil};

	#[tokio::test]
	async fn test_attest() {
		let anvil = Anvil::new().spawn();
		let config = ClientConfig {
			as_address: "0x5fbdb2315678afecb367f032d93f642f64180aa3".to_string(),
			band_id: "38922764296632428858395574229367".to_string(),
			band_th: "500".to_string(),
			band_url: "http://localhost:3000".to_string(),
			domain: "0x0000000000000000000000000000000000000000".to_string(),
			node_url: anvil.endpoint().to_string(),
			verifier_address: "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512".to_string(),
		};
		let client = Client::new(config);

		// Deploy attestation station and verifier
		let as_address = deploy_as(client.get_signer()).await.unwrap();
		let verifier_address =
			deploy_verifier(client.get_signer(), read_bytes_data("et_verifier")).await.unwrap();

		// Update config with new addresses
		let config = ClientConfig {
			as_address: format!("{:?}", as_address),
			band_id: "38922764296632428858395574229367".to_string(),
			band_th: "500".to_string(),
			band_url: "http://localhost:3000".to_string(),
			domain: "0x0000000000000000000000000000000000000000".to_string(),
			node_url: anvil.endpoint().to_string(),
			verifier_address: format!("{:?}", verifier_address),
		};

		// Attest
		let attestation = Attestation::new(Address::default(), H256::default(), 1, None);
		assert!(Client::new(config).attest(attestation).await.is_ok());

		drop(anvil);
	}

	#[tokio::test]
	async fn test_get_attestations() {
		let anvil = Anvil::new().spawn();
		let config = ClientConfig {
			as_address: "0x5fbdb2315678afecb367f032d93f642f64180aa3".to_string(),
			band_id: "38922764296632428858395574229367".to_string(),
			band_th: "500".to_string(),
			band_url: "http://localhost:3000".to_string(),
			domain: "0x0000000000000000000000000000000000000000".to_string(),
			node_url: anvil.endpoint().to_string(),
			verifier_address: "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512".to_string(),
		};
		let client = Client::new(config);

		// Deploy attestation station and verifier
		let as_address = deploy_as(client.get_signer()).await.unwrap();
		let verifier_address =
			deploy_verifier(client.get_signer(), read_bytes_data("et_verifier")).await.unwrap();

		// Update config with new addresses and instantiate client
		let config = ClientConfig {
			as_address: format!("{:?}", as_address),
			band_id: "38922764296632428858395574229367".to_string(),
			band_th: "500".to_string(),
			band_url: "http://localhost:3000".to_string(),
			domain: "0x0000000000000000000000000000000000000000".to_string(),
			node_url: anvil.endpoint().to_string(),
			verifier_address: format!("{:?}", verifier_address),
		};
		let client = Client::new(config);

		// Build Attestation
		let about_bytes = [
			0xff, 0x61, 0x4a, 0x6d, 0x59, 0x56, 0x2a, 0x42, 0x37, 0x72, 0x37, 0x76, 0x32, 0x4d,
			0x36, 0x53, 0x62, 0x6d, 0x35, 0xff,
		];

		// Build key
		let mut key_bytes: [u8; 32] = [0; 32];
		key_bytes[..DOMAIN_PREFIX_LEN].copy_from_slice(&DOMAIN_PREFIX);

		let message = [
			0x00, 0x75, 0x32, 0x45, 0x75, 0x79, 0x32, 0x77, 0x7a, 0x34, 0x58, 0x6c, 0x34, 0x34,
			0x4a, 0x74, 0x6a, 0x78, 0x68, 0x4c, 0x4a, 0x52, 0x67, 0x48, 0x45, 0x6c, 0x4e, 0x73,
			0x65, 0x6e, 0x79, 0x00,
		];

		let attestation = Attestation::new(
			Address::from(about_bytes),
			H256::from(key_bytes),
			10,
			Some(H256::from(message)),
		);

		client.attest(attestation.clone()).await.unwrap();

		let attestations = client.get_attestations().await.unwrap();

		assert_eq!(attestations.len(), 1);

		let (_, returned_att) = attestations[0].clone();

		// Check that the attestations match
		assert_eq!(returned_att.about, attestation.about);
		assert_eq!(returned_att.key, attestation.key);
		assert_eq!(returned_att.value, attestation.value);
		assert_eq!(returned_att.message, attestation.message);

		drop(anvil);
	}
}
