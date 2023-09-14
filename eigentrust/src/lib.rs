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
		dynamic_sets::native::EigenTrustSet as NativeEigenTrustSet, threshold::native::Threshold,
		EigenTrust4, NativeEigenTrust4, PoseidonNativeHasher, PoseidonNativeSponge, HASHER_WIDTH,
		MIN_PEER_COUNT, NUM_BITS, NUM_LIMBS,
	},
	ecdsa::native::{EcdsaKeypair, PublicKey, Signature},
	halo2::{
		arithmetic::Field,
		halo2curves::{
			bn256::{self, Bn256},
			secp256k1::{Fq, Secp256k1Affine},
		},
		plonk::ProvingKey,
		poly::{commitment::Params as KZGParams, kzg::commitment::ParamsKZG},
		SerdeFormat,
	},
	params::{
		ecc::secp256k1::Secp256k1Params, hasher::poseidon_bn254_5x5::Params,
		rns::secp256k1::Secp256k1_4_68,
	},
	poseidon::native::Poseidon,
	utils::{generate_params, keygen, prove},
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
/// Outbound local trust vector.
pub type OpinionVector = Vec<Option<SignedAttestationScalar>>;

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

/// Eigentrust circuit public input parameters
pub struct ETPublicInputs {
	/// Participants' set
	pub participants: Vec<Scalar>,
	/// Participants' scores
	pub scores: Vec<Scalar>,
	/// Domain
	pub domain: Scalar,
	/// Opinions' hash
	pub opinion_hash: Scalar,
}

impl ETPublicInputs {
	/// Creates a new ETPublicparams instance.
	pub fn new(
		participants: Vec<Scalar>, scores: Vec<Scalar>, domain: Scalar, opinion_hash: Scalar,
	) -> Self {
		Self { participants, scores, domain, opinion_hash }
	}

	/// Returns the struct as a concatenated Vec<Scalar>.
	pub fn to_vec(&self) -> Vec<Scalar> {
		let mut result = Vec::new();
		result.extend(self.participants.iter().cloned());
		result.extend(self.scores.iter().cloned());
		result.push(self.domain);
		result.push(self.opinion_hash);

		result
	}
}

/// Scores report struct.
pub struct ScoresReport {
	/// Participants' scores
	pub scores: Vec<Score>,
	/// Verifier public inputs
	pub pub_inputs: ETPublicInputs,
	/// Proof
	pub proof: Vec<u8>,
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

	/// Generates new KZG params (Mostly used for testing)
	pub fn generate_params(k: u32) -> Vec<u8> {
		let params = generate_params::<Bn256>(k);
		let mut buffer: Vec<u8> = Vec::new();
		params.write(&mut buffer).expect("Failed to generate KZG params");
		buffer
	}

	/// Generates new proving key for EigenTrust circuit
	pub fn generate_et_pk(params_bytes: Vec<u8>) -> Result<Vec<u8>, EigenError> {
		let rng = &mut rand::thread_rng();

		let opt_att = vec![vec![None; NUM_ITERATIONS]; NUM_ITERATIONS];
		let opt_pks = vec![None; NUM_ITERATIONS];
		let domain = Scalar::random(rng);
		let et = EigenTrust4::new(opt_att, opt_pks, domain);

		let mut params_slice = params_bytes.as_slice();
		let params =
			ParamsKZG::<Bn256>::read(&mut params_slice).expect("Failed to read KZG params");
		let pk = keygen(&params, et)
			.map_err(|_| EigenError::KeygenError("Failed to generate pk/vk pair".to_string()))?;
		Ok(pk.to_bytes(SerdeFormat::Processed))
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
		&self, att: Vec<SignedAttestationRaw>, proving_key: Vec<u8>,
	) -> Result<ScoresReport, EigenError> {
		// Get signed attestations
		let attestations: Vec<SignedAttestationEth> =
			att.into_iter().map(|signed_raw| signed_raw.into()).collect();

		// Initialize set to get participants
		let mut btree_set: BTreeSet<Address> = BTreeSet::new();

		// Create (Address -> ECDSA Public Key) map
		let mut pub_key_map = HashMap::new();

		for signed_att in &attestations {
			let pub_key: ECDSAPublicKey = signed_att.recover_public_key()?;
			let att_origin: Address = address_from_ecdsa_key(&pub_key);

			pub_key_map.insert(att_origin, pub_key);
			btree_set.insert(signed_att.attestation.about);
			btree_set.insert(att_origin);
		}

		// Build participants set
		// The participants' set order defines the attestations' order
		let address_set: Vec<Address> = btree_set.clone().into_iter().collect();

		// Verify that the participants set is not larger than the maximum number of participants
		assert!(
			address_set.len() <= MAX_NEIGHBOURS,
			"Number of participants exceeds maximum number of neighbours"
		);
		// Verify that the number of participants is greater than the minimum number of participants
		assert!(
			address_set.len() >= MIN_PEER_COUNT,
			"Number of participants is less than the minimum number of neighbours"
		);

		// Build Scalar set
		let scalar_set: Vec<Scalar> = btree_set
			.into_iter()
			.map(|participant| scalar_from_address(&participant))
			.collect::<Result<Vec<Scalar>, _>>()?;

		// Setup circuit ECDSA public keys vector
		let mut ecdsa_pub_keys: Vec<Option<ECDSAPublicKey>> = Vec::with_capacity(MAX_NEIGHBOURS);
		for index in 0..MAX_NEIGHBOURS {
			let key = if index < address_set.len() {
				pub_key_map.get(&address_set[index]).cloned()
			} else {
				None
			};

			ecdsa_pub_keys.push(key);
		}

		// Initialize attestation matrix
		let mut attestation_matrix: Vec<OpinionVector> =
			vec![vec![None; MAX_NEIGHBOURS]; MAX_NEIGHBOURS];

		// Populate the attestation matrix with the attestations data
		for signed_att in &attestations {
			let pub_key: ECDSAPublicKey = signed_att.recover_public_key()?;
			let att_origin: Address = address_from_ecdsa_key(&pub_key);

			// Get attestation origin and destination indexes in the set
			let origin_index = address_set.iter().position(|&r| r == att_origin).unwrap();
			let dest_index =
				address_set.iter().position(|&r| r == signed_att.attestation.about).unwrap();

			// Get scalar signed attestations
			let scalar_att: SignedAttestationScalar = signed_att.to_signed_signature_fr()?;

			// Fill matrix
			attestation_matrix[origin_index][dest_index] = Some(scalar_att);
		}

		// Build domain
		let scalar_domain = self.get_scalar_domain()?;

		// Initialize Native Set
		let mut native_et = NativeEigenTrust4::new(scalar_domain);

		// Add participants to native set
		for member in scalar_set.clone() {
			native_et.add_member(member);
		}

		// Submit participants' opinion to native set and get opinion hashes
		let mut op_hashes: Vec<Scalar> = Vec::new();
		for (origin_index, member) in address_set.clone().into_iter().enumerate() {
			if let Some(pub_key) = pub_key_map.get(&member) {
				let opinion = attestation_matrix[origin_index].clone();
				op_hashes.push(native_et.update_op(pub_key.clone(), opinion));
			}
		}

		// Calculate scores
		let rational_scores = native_et.converge_rational();
		let scalar_scores: Vec<Scalar> = native_et.converge();

		// Verify that the scores vectors are of equal length
		assert_eq!(
			scalar_scores.len(),
			rational_scores.len(),
			"Scores vectors are not of equal length"
		);
		// Verify that the scores vector is at least as long as the participants vector
		assert!(
			scalar_scores.len() >= address_set.len(),
			"There are more participants than scores"
		);

		// Construct scores vec
		let scores: Vec<Score> = address_set
			.iter()
			.zip(scalar_scores.iter())
			.zip(rational_scores.iter())
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

		// Generate opinions' sponge hash.
		let mut sponge = PoseidonNativeSponge::new();
		sponge.update(&op_hashes);
		let opinions_hash = sponge.squeeze();

		// Initialize EigenTrustSet
		let et_circuit: EigenTrust4 =
			EigenTrust4::new(attestation_matrix, ecdsa_pub_keys, scalar_domain);

		// Generate KZG params
		let k = 20;
		let raw_params = Client::generate_params(k);
		let parsed_params: ParamsKZG<Bn256> =
			ParamsKZG::<Bn256>::read(&mut raw_params.as_slice()).unwrap();

		// Generate proving key
		let raw_prov_key = Client::generate_et_pk(raw_params).unwrap();
		let proving_key: ProvingKey<bn256::G1Affine> =
			ProvingKey::from_bytes::<EigenTrust4>(&raw_prov_key, SerdeFormat::Processed).unwrap();

		// Build public inputs
		let pub_inputs = ETPublicInputs::new(
			scalar_set,
			scalar_scores.clone(),
			scalar_domain,
			opinions_hash,
		);

		let rng = &mut rand::thread_rng();
		let proof = prove::<Bn256, _, _>(
			&parsed_params,
			et_circuit,
			&[&pub_inputs.to_vec()],
			&proving_key,
			rng,
		)
		.unwrap();

		Ok(ScoresReport { scores, pub_inputs, proof })
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

	/// Gets the domain as BN256 scalar.
	pub fn get_scalar_domain(&self) -> Result<Scalar, EigenError> {
		let domain_bytes = H160::from_str(&self.config.domain)
			.map_err(|e| EigenError::ParsingError(format!("Error parsing domain: {}", e)))?;
		let domain_opt = Scalar::from_bytes(H256::from(domain_bytes).as_fixed_bytes());

		match domain_opt.is_some().into() {
			true => Ok(domain_opt.unwrap()),
			false => Err(EigenError::ParsingError(
				"Failed to construct scalar domain".to_string(),
			)),
		}
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
