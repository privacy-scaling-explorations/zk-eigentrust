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
// Clippy
#![allow(clippy::tabs_in_doc_comments, clippy::needless_range_loop, clippy::new_without_default)]
#![deny(
	// Complexity
 	clippy::unnecessary_cast,
	clippy::needless_question_mark,
	clippy::clone_on_copy,
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

use crate::attestation::{
	SignatureEth, SignatureRaw, SignedAttestationEth, SignedAttestationScalar,
};
use att_station::{
	AttestationCreatedFilter, AttestationData as ContractAttestationData, AttestationStation,
};
use attestation::{AttestationEth, AttestationRaw, SignedAttestationRaw};
use eigentrust_zk::{
	circuits::{
		dynamic_sets::native::EigenTrustSet, threshold::native::Threshold, PoseidonNativeHasher,
		PoseidonNativeSponge, HASHER_WIDTH, MIN_PEER_COUNT, NUM_BITS, NUM_LIMBS,
	},
	ecdsa::native::{EcdsaKeypair, PublicKey, Signature},
	halo2::halo2curves::{
		bn256,
		secp256k1::{Fq, Secp256k1Affine},
	},
	params::{
		ecc::secp256k1::Secp256k1Params, hasher::poseidon_bn254_5x5::Params,
		rns::secp256k1::Secp256k1_4_68,
	},
	poseidon::native::Poseidon,
};
use error::EigenError;
use eth::{address_from_ecdsa_key, ecdsa_keypairs_from_mnemonic, scalar_from_address};
use ethers::{
	abi::{Address, RawLog},
	contract::EthEvent,
	middleware::SignerMiddleware,
	prelude::EthDisplay,
	providers::{Http, Middleware, Provider},
	signers::{coins_bip39::English, LocalWallet, MnemonicBuilder, Signer},
	types::{Filter, Log, H160, H256},
};
use log::{info, warn};
use num_rational::BigRational;
use serde::{Deserialize, Serialize};
use std::{
	collections::{BTreeSet, HashMap},
	str::FromStr,
	sync::Arc,
};

/// Max amount of participants.
const MAX_NEIGHBOURS: usize = 4;
/// Number of iterations to run the eigen trust algorithm.
const NUM_ITERATIONS: usize = 20;
/// Initial score for each participant before the algorithms is run.
const INITIAL_SCORE: u128 = 1000;
/// Number of limbs for representing big numbers in threshold checking.
const NUM_DECIMAL_LIMBS: usize = 2;
/// Number of digits of each limbs for threshold checking.
const POWER_OF_TEN: usize = 72;

/// Client Signer.
pub type ClientSigner = SignerMiddleware<Provider<Http>, LocalWallet>;
/// Scalar type.
pub type Scalar = bn256::Fr;
/// SECP Scalar type.
pub type SecpScalar = Fq;
/// ECDSA public key.
pub type ECDSAPublicKey =
	PublicKey<Secp256k1Affine, Scalar, NUM_LIMBS, NUM_BITS, Secp256k1_4_68, Secp256k1Params>;
/// ECDSA keypair.
pub type ECDSAKeypair =
	EcdsaKeypair<Secp256k1Affine, Scalar, NUM_LIMBS, NUM_BITS, Secp256k1_4_68, Secp256k1Params>;
/// ECDSA signature.
pub type ECDSASignature = Signature<Secp256k1Affine, Scalar, NUM_LIMBS, NUM_BITS, Secp256k1_4_68>;

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
	/// Network chain ID.
	pub chain_id: String,
	/// Attestation domain identifier.
	pub domain: String,
	/// Ethereum node URL.
	pub node_url: String,
}

/// Score struct.
pub struct Score {
	/// Participant address.
	pub address: [u8; 20],
	/// Scalar score.
	pub score_fr: [u8; 32],
	/// Rational score (numerator, denominator).
	pub score_rat: ([u8; 32], [u8; 32]),
	/// Hexadecimal score.
	pub score_hex: [u8; 32],
}

/// Client struct.
pub struct Client {
	signer: Arc<ClientSigner>,
	config: ClientConfig,
	mnemonic: String,
}

impl Client {
	/// Creates a new Client instance.
	pub fn new(config: ClientConfig, mnemonic: String) -> Self {
		// Setup provider
		let provider = Provider::<Http>::try_from(&config.node_url)
			.expect("Failed to create provider from config node url");

		// Setup wallet
		let wallet = MnemonicBuilder::<English>::default()
			.phrase(mnemonic.as_str())
			.build()
			.expect("Failed to build wallet with provided mnemonic");

		// Setup signer
		let chain_id: u64 = config.chain_id.parse().expect("Failed to parse chain id");
		let signer: ClientSigner = SignerMiddleware::new(provider, wallet.with_chain_id(chain_id));

		// Arc for thread-safe sharing of signer
		let shared_signer = Arc::new(signer);

		Self { signer: shared_signer, config, mnemonic }
	}

	/// Submits an attestation to the attestation station.
	pub async fn attest(&self, attestation: AttestationRaw) -> Result<(), EigenError> {
		let rng = &mut rand::thread_rng();
		let keypairs = ecdsa_keypairs_from_mnemonic(&self.mnemonic, 1)?;

		let attestation_eth = AttestationEth::from(attestation);
		let attestation_fr = attestation_eth.to_attestation_fr()?;

		// Format for signature
		let att_hash = attestation_fr
			.hash::<HASHER_WIDTH, Poseidon<Scalar, HASHER_WIDTH, Params>>()
			.to_bytes();
		let attestation_fq = SecpScalar::from_bytes(&att_hash).unwrap();

		// Sign
		let signature = keypairs[0].sign(attestation_fq, rng);

		let signature_raw = SignatureRaw::from(signature);
		let signature_eth = SignatureEth::from(signature_raw);

		let signed_attestation = SignedAttestationEth::new(attestation_eth, signature_eth);

		let as_address_res = self.config.as_address.parse::<Address>();
		let as_address = as_address_res.map_err(|e| EigenError::ParsingError(e.to_string()))?;
		let as_contract = AttestationStation::new(as_address, self.signer.clone());

		// Verify signature is recoverable
		let recovered_pubkey = signed_attestation.recover_public_key()?;
		let recovered_address = address_from_ecdsa_key(&recovered_pubkey);
		assert!(recovered_address == self.signer.address());

		// Stored contract data
		let (_, about, key, payload) = signed_attestation.to_tx_data()?;
		let contract_data =
			ContractAttestationData { about, key: key.to_fixed_bytes(), val: payload };

		let tx_call = as_contract.attest(vec![contract_data]);
		let tx_res = tx_call.send().await;
		let tx = tx_res
			.map_err(|_| EigenError::TransactionError("Transaction send failed".to_string()))?;
		let res = tx.await.map_err(|_| {
			EigenError::TransactionError("Transaction resolution failed".to_string())
		})?;

		if let Some(receipt) = res {
			info!("Transaction status: {:?}", receipt.status);
		}

		Ok(())
	}

	/// Calculates the EigenTrust global scores.
	pub async fn calculate_scores(
		&self, att: Vec<SignedAttestationRaw>,
	) -> Result<Vec<Score>, EigenError> {
		// Parse attestation logs into signed attestation and attestation structs
		let attestations: Vec<SignedAttestationEth> =
			att.into_iter().map(|signed_raw| signed_raw.into()).collect();

		// Construct a set to hold unique participant addresses
		let mut participants_set = BTreeSet::<Address>::new();
		let mut pks = HashMap::new();

		// Insert the attester and attested of each attestation into the set
		for signed_att in &attestations {
			let public_key = signed_att.recover_public_key()?;
			let attester = address_from_ecdsa_key(&public_key);
			participants_set.insert(signed_att.attestation.about);
			participants_set.insert(attester);

			let pk = signed_att.recover_public_key()?;
			pks.insert(attester, pk);
		}

		// Create a vector of participants from the set
		let participants: Vec<Address> = participants_set.into_iter().collect();

		// Verify that the participants set is not larget than the maximum number of participants
		assert!(
			participants.len() <= MAX_NEIGHBOURS,
			"Number of participants exceeds maximum number of neighbours"
		);

		// Verify that the number of participants is greater than the minimum number of participants
		assert!(
			participants.len() >= MIN_PEER_COUNT,
			"Number of participants is less than the minimum number of neighbours"
		);

		// Initialize attestation matrix
		let mut attestation_matrix: Vec<Vec<Option<SignedAttestationScalar>>> =
			vec![vec![None; MAX_NEIGHBOURS]; MAX_NEIGHBOURS];

		// Populate the attestation matrix with the attestations data
		for signed_att in &attestations {
			let public_key = signed_att.recover_public_key()?;
			let attester = address_from_ecdsa_key(&public_key);
			let attester_pos = participants.iter().position(|&r| r == attester).unwrap();
			let attested_pos =
				participants.iter().position(|&r| r == signed_att.attestation.about).unwrap();

			let signed_attestation_fr = signed_att.to_signed_signature_fr()?;
			attestation_matrix[attester_pos][attested_pos] = Some(signed_attestation_fr);
		}

		// Build domain
		let domain_bytes: H160 = H160::from_str(&self.config.domain)
			.map_err(|e| EigenError::ParsingError(format!("Error parsing domain: {}", e)))?;
		let domain = Scalar::from_bytes(H256::from(domain_bytes).as_fixed_bytes()).unwrap();

		// Initialize EigenTrustSet
		let mut eigen_trust_set = EigenTrustSet::<
			MAX_NEIGHBOURS,
			NUM_ITERATIONS,
			INITIAL_SCORE,
			Secp256k1Affine,
			Scalar,
			NUM_LIMBS,
			NUM_BITS,
			Secp256k1_4_68,
			Secp256k1Params,
			PoseidonNativeHasher,
			PoseidonNativeSponge,
		>::new(domain);

		// Add participants to set
		for participant in &participants {
			let participant_fr = scalar_from_address(participant)?;
			eigen_trust_set.add_member(participant_fr);
		}

		// Update the set with the opinions of each participant
		for i in 0..participants.len() {
			let addr = participants[i];
			if let Some(pk) = pks.get(&addr) {
				let opinion = attestation_matrix[i].clone();
				eigen_trust_set.update_op(pk.clone(), opinion);
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
				let address = participant.to_fixed_bytes();

				let mut scalar = score_fr.to_bytes();
				scalar.reverse();

				let num_bytes = score_rat.numer().to_bytes_be().1;
				let den_bytes = score_rat.denom().to_bytes_be().1;
				let score_bytes = score_rat.to_integer().to_bytes_be().1;

				let mut numerator: [u8; 32] = [0; 32];
				numerator[32 - num_bytes.len()..].copy_from_slice(&num_bytes);

				let mut denominator: [u8; 32] = [0; 32];
				denominator[32 - den_bytes.len()..].copy_from_slice(&den_bytes);

				let mut score_hex: [u8; 32] = [0; 32];
				score_hex[32 - score_bytes.len()..].copy_from_slice(&score_bytes);

				Score { address, score_fr: scalar, score_rat: (numerator, denominator), score_hex }
			})
			.collect();

		Ok(scores)
	}

	/// Fetches attestations from the contract.
	pub async fn get_attestations(&self) -> Result<Vec<SignedAttestationRaw>, EigenError> {
		let att_logs: Result<Vec<AttestationCreatedFilter>, EigenError> = self
			.get_logs()
			.await?
			.iter()
			.map(|log| {
				let raw_log = RawLog::from((log.topics.clone(), log.data.to_vec()));
				AttestationCreatedFilter::decode_log(&raw_log)
					.map_err(|e| EigenError::ParsingError(e.to_string()))
			})
			.collect();

		// Convert logs into signed attestations
		let signed_attestations: Result<Vec<SignedAttestationRaw>, _> = att_logs?
			.into_iter()
			.map(|log| {
				let att_raw: AttestationRaw = log.clone().try_into()?;
				let sig_raw: SignatureRaw = log.try_into()?;
				Ok(SignedAttestationRaw::new(att_raw, sig_raw))
			})
			.collect();

		signed_attestations
	}

	/// Fetches logs from the contract.
	pub async fn get_logs(&self) -> Result<Vec<Log>, EigenError> {
		let filter = Filter::new()
			.address(self.config.as_address.parse::<Address>().unwrap())
			.event("AttestationCreated(address,address,bytes32,bytes)")
			.topic1(Vec::<H256>::new())
			.topic2(Vec::<H256>::new())
			.from_block(0);

		self.signer.get_logs(&filter).await.map_err(|e| EigenError::ParsingError(e.to_string()))
	}

	/// Verifies last generated proof.
	pub async fn verify(&self) -> Result<(), EigenError> {
		// TODO: Verify proof
		Ok(())
	}

	/// Gets config.
	pub fn get_config(&self) -> &ClientConfig {
		&self.config
	}

	/// Gets signer.
	pub fn get_signer(&self) -> Arc<ClientSigner> {
		self.signer.clone()
	}

	/// Verifies if a participant's score surpasses the score threshold.
	pub fn verify_threshold(score: u64, score_num: u64, score_den: u64, threshold: u64) -> bool {
		let score_fr = Scalar::from(score);
		let threshold_fr = Scalar::from(threshold);
		let score_ratio = BigRational::new(score_num.into(), score_den.into());

		let th_circuit: Threshold<
			Scalar,
			NUM_DECIMAL_LIMBS,
			POWER_OF_TEN,
			MAX_NEIGHBOURS,
			INITIAL_SCORE,
		> = Threshold::new(score_fr, score_ratio, threshold_fr);

		th_circuit.check_threshold()
	}
}

#[cfg(test)]
mod lib_tests {
	use crate::{attestation::AttestationRaw, eth::deploy_as, Client, ClientConfig};
	use ethers::utils::Anvil;

	const TEST_MNEMONIC: &'static str =
		"test test test test test test test test test test test junk";

	#[tokio::test]
	async fn test_attest() {
		let anvil = Anvil::new().spawn();
		let config = ClientConfig {
			as_address: "0x5fbdb2315678afecb367f032d93f642f64180aa3".to_string(),
			band_id: "38922764296632428858395574229367".to_string(),
			band_th: "500".to_string(),
			band_url: "http://localhost:3000".to_string(),
			chain_id: "31337".to_string(),
			domain: "0x0000000000000000000000000000000000000000".to_string(),
			node_url: anvil.endpoint().to_string(),
		};
		let client = Client::new(config, TEST_MNEMONIC.to_string());

		// Deploy attestation station
		let as_address = deploy_as(client.get_signer()).await.unwrap();

		// Update config with new addresses
		let updated_config = ClientConfig {
			as_address: format!("{:?}", as_address),
			band_id: "38922764296632428858395574229367".to_string(),
			band_th: "500".to_string(),
			band_url: "http://localhost:3000".to_string(),
			chain_id: "31337".to_string(),
			domain: "0x0000000000000000000000000000000000000000".to_string(),
			node_url: anvil.endpoint().to_string(),
		};

		let updated_client = Client::new(updated_config, TEST_MNEMONIC.to_string());

		// Attest
		let attestation = AttestationRaw::new([0; 20], [0; 20], 5, [0; 32]);
		assert!(updated_client.attest(attestation).await.is_ok());

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
			chain_id: "31337".to_string(),
			domain: "0x0000000000000000000000000000000000000000".to_string(),
			node_url: anvil.endpoint().to_string(),
		};
		let client = Client::new(config, TEST_MNEMONIC.to_string());

		// Deploy attestation station
		let as_address = deploy_as(client.get_signer()).await.unwrap();

		// Update config with new addresses and instantiate client
		let config = ClientConfig {
			as_address: format!("{:?}", as_address),
			band_id: "38922764296632428858395574229367".to_string(),
			band_th: "500".to_string(),
			band_url: "http://localhost:3000".to_string(),
			chain_id: "31337".to_string(),
			domain: "0x0000000000000000000000000000000000000000".to_string(),
			node_url: anvil.endpoint().to_string(),
		};
		let client = Client::new(config, TEST_MNEMONIC.to_string());

		// Build Attestation
		let about_bytes = [
			0xff, 0x61, 0x4a, 0x6d, 0x59, 0x56, 0x2a, 0x42, 0x37, 0x72, 0x37, 0x76, 0x32, 0x4d,
			0x36, 0x53, 0x62, 0x6d, 0x35, 0xff,
		];

		let domain_input = [
			0xff, 0x61, 0x4a, 0x6d, 0x59, 0x56, 0x2a, 0x42, 0x37, 0x72, 0x37, 0x76, 0x32, 0x4d,
			0x36, 0x53, 0x62, 0x6d, 0x35, 0xff,
		];

		let value: u8 = 10;

		let message = [
			0x00, 0x75, 0x32, 0x45, 0x75, 0x79, 0x32, 0x77, 0x7a, 0x34, 0x58, 0x6c, 0x34, 0x34,
			0x4a, 0x74, 0x6a, 0x78, 0x68, 0x4c, 0x4a, 0x52, 0x67, 0x48, 0x45, 0x6c, 0x4e, 0x73,
			0x65, 0x6e, 0x79, 0x00,
		];

		let attestation = AttestationRaw::new(about_bytes, domain_input, value, message);

		client.attest(attestation.clone()).await.unwrap();

		let attestations = client.get_attestations().await.unwrap();

		assert_eq!(attestations.len(), 1);

		let fetched_att = attestations[0].clone().attestation;

		// Check that the attestations match
		assert_eq!(fetched_att.about, about_bytes);
		assert_eq!(fetched_att.domain, domain_input);
		assert_eq!(fetched_att.value, value);
		assert_eq!(fetched_att.message, message);

		drop(anvil);
	}
}
