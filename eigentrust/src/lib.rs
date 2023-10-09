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
pub mod circuit;
pub mod error;
pub mod eth;
pub mod storage;

use crate::{
	attestation::{SignatureEth, SignatureRaw, SignedAttestationEth, SignedAttestationScalar},
	circuit::{ETPublicInputs, OpinionVector, Score},
};
use att_station::{
	AttestationCreatedFilter, AttestationData as ContractAttestationData, AttestationStation,
};
use attestation::{build_att_key, AttestationEth, AttestationRaw, SignedAttestationRaw};
use circuit::{ETReport, ETSetup, ThPublicInputs, ThReport, ThSetup};
use eigentrust_zk::{
	circuits::{
		threshold::native::Threshold, ECDSAPublicKey, EigenTrust4, NativeAggregator4,
		NativeEigenTrust4, NativeThreshold4, PoseidonNativeSponge, Threshold4, HASHER_WIDTH,
		MIN_PEER_COUNT, NUM_DECIMAL_LIMBS, NUM_ITERATIONS, NUM_NEIGHBOURS, POWER_OF_TEN,
	},
	halo2::{
		arithmetic::Field,
		halo2curves::{
			bn256::{Bn256, Fr as Scalar, G1Affine},
			secp256k1::Fq as SecpScalar,
		},
		plonk::ProvingKey,
		poly::{commitment::Params as KZGParams, kzg::commitment::ParamsKZG},
		SerdeFormat,
	},
	params::hasher::poseidon_bn254_5x5::Params,
	poseidon::native::Poseidon,
	utils::{big_to_fe_rat, generate_params, keygen, prove, verify},
	verifier::aggregator::native::Snark,
};
use error::EigenError;
use eth::{address_from_ecdsa_key, ecdsa_keypairs_from_mnemonic, scalar_from_address};
use ethers::{
	abi::{Address, RawLog},
	contract::EthEvent,
	middleware::SignerMiddleware,
	providers::{Http, Middleware, Provider},
	signers::{coins_bip39::English, LocalWallet, MnemonicBuilder, Signer},
	types::{Log, H160, H256},
};
use log::{debug, info, warn};
use num_rational::BigRational;
use rand::thread_rng;
use std::{
	collections::{BTreeSet, HashMap},
	sync::Arc,
	time::Instant,
};

/// Client Signer.
pub type ClientSigner = SignerMiddleware<Provider<Http>, LocalWallet>;

/// Client struct.
pub struct Client {
	as_address: Address,
	domain: H160,
	mnemonic: String,
	signer: Arc<ClientSigner>,
}

impl Client {
	/// Creates a new Client instance.
	pub fn new(
		mnemonic: String, chain_id: u32, as_address: [u8; 20], domain: [u8; 20], node_url: String,
	) -> Self {
		// Setup provider
		let provider = Provider::<Http>::try_from(&node_url)
			.expect("Failed to create provider from config node url");

		// Setup wallet
		let wallet = MnemonicBuilder::<English>::default()
			.phrase(mnemonic.as_str())
			.build()
			.expect("Failed to build wallet with provided mnemonic");

		// Setup signer
		let signer: ClientSigner = SignerMiddleware::new(provider, wallet.with_chain_id(chain_id));

		// Arc for thread-safe sharing of signer
		let shared_signer = Arc::new(signer);

		Self {
			signer: shared_signer,
			mnemonic,
			as_address: Address::from(as_address),
			domain: H160::from(domain),
		}
	}

	/// Gets signer.
	pub fn get_signer(&self) -> Arc<ClientSigner> {
		self.signer.clone()
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

		let as_contract = AttestationStation::new(self.as_address, self.signer.clone());

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
	pub fn calculate_scores(
		&self, att: Vec<SignedAttestationRaw>,
	) -> Result<Vec<Score>, EigenError> {
		let et_setup = self.et_circuit_setup(att)?;

		// Construct scores vec
		let scores: Vec<Score> = et_setup
			.address_set
			.iter()
			.zip(et_setup.pub_inputs.scores.iter())
			.zip(et_setup.rational_scores.iter())
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

	/// Generates an EigenTrust circuit proof.
	pub fn generate_et_proof(
		&self, att: Vec<SignedAttestationRaw>, raw_kzg_params: Vec<u8>, raw_prov_key: Vec<u8>,
	) -> Result<ETReport, EigenError> {
		let rng = &mut rand::thread_rng();
		let et_setup = self.et_circuit_setup(att)?;

		// Parse KZG params and proving key
		let kzg_params: ParamsKZG<Bn256> =
			ParamsKZG::<Bn256>::read(&mut raw_kzg_params.as_slice()).unwrap();
		let proving_key: ProvingKey<G1Affine> =
			ProvingKey::from_bytes::<EigenTrust4>(&raw_prov_key, SerdeFormat::Processed).unwrap();

		// Initialize EigenTrustSet
		let et_circuit: EigenTrust4 = EigenTrust4::new(
			et_setup.attestation_matrix,
			et_setup.ecdsa_set,
			self.get_scalar_domain()?,
		);

		// Generate proof
		let proof = prove::<Bn256, _, _>(
			&kzg_params,
			et_circuit,
			&[&et_setup.pub_inputs.to_vec()],
			&proving_key,
			rng,
		)
		.map_err(|e| EigenError::ProvingError(format!("Failed to generate proof: {}", e)))?;

		Ok(ETReport { pub_inputs: et_setup.pub_inputs, proof })
	}

	/// Generates Threshold circuit proof for the selected participant.
	pub fn generate_th_proof(
		&self, att: Vec<SignedAttestationRaw>, raw_et_kzg_params: Vec<u8>,
		raw_th_kzg_params: Vec<u8>, raw_proving_key: Vec<u8>, threshold: u32,
		participant: [u8; 20],
	) -> Result<ThReport, EigenError> {
		let rng = &mut thread_rng();
		let th_setup = self.th_circuit_setup(att, raw_et_kzg_params, threshold, participant)?;

		// Build kzg params and proving key
		let th_kzg_params =
			ParamsKZG::<Bn256>::read(&mut raw_th_kzg_params.as_slice()).map_err(|e| {
				EigenError::ReadWriteError(format!("Failed to read TH KZG params: {}", e))
			})?;
		let proving_key = ProvingKey::<G1Affine>::from_bytes::<Threshold4>(
			&raw_proving_key,
			SerdeFormat::Processed,
		)
		.map_err(|_| EigenError::ProvingError("Failed to parse proving key".to_string()))?;

		let proof = prove::<Bn256, _, _>(
			&th_kzg_params,
			th_setup.circuit,
			&[&th_setup.pub_inputs.to_vec()],
			&proving_key,
			rng,
		)
		.map_err(|e| EigenError::ProvingError(format!("Failed to generate proof: {}", e)))?;

		Ok(ThReport { proof, pub_inputs: th_setup.pub_inputs })
	}

	/// Verifies the given proof.
	pub fn verify(
		&self, raw_kzg_params: Vec<u8>, raw_public_inputs: Vec<u8>, raw_proving_key: Vec<u8>,
		proof: Vec<u8>,
	) -> Result<(), EigenError> {
		// Parse KZG params
		let kzg_params: ParamsKZG<Bn256> = ParamsKZG::read(&mut raw_kzg_params.as_slice())
			.map_err(|e| EigenError::ParsingError(e.to_string()))?;

		// Parse public inputs
		let pub_inputs: ETPublicInputs =
			ETPublicInputs::from_bytes(raw_public_inputs, NUM_NEIGHBOURS)?;

		// Parse proving key
		let proving_key: ProvingKey<G1Affine> =
			ProvingKey::from_bytes::<EigenTrust4>(&raw_proving_key, SerdeFormat::Processed)
				.map_err(|e| EigenError::ParsingError(e.to_string()))?;

		// Verify
		let is_verified = verify(
			&kzg_params,
			&[&pub_inputs.to_vec()],
			&proof,
			proving_key.get_vk(),
		)
		.map_err(|e| EigenError::VerificationError(e.to_string()));

		match is_verified? {
			true => Ok(()),
			false => Err(EigenError::VerificationError(
				"Verification failed".to_string(),
			)),
		}
	}

	/// Returns a built eigen trust circuit and relevant circuit data.
	pub fn et_circuit_setup(&self, att: Vec<SignedAttestationRaw>) -> Result<ETSetup, EigenError> {
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
			address_set.len() <= NUM_NEIGHBOURS,
			"Number of participants exceeds maximum number of neighbours"
		);
		// Verify that the number of participants is greater than the minimum number of participants
		assert!(
			address_set.len() >= MIN_PEER_COUNT,
			"Number of participants is less than the minimum number of neighbours"
		);

		// Build Scalar set
		let mut scalar_set: Vec<Scalar> = btree_set
			.into_iter()
			.map(|participant| scalar_from_address(&participant))
			.collect::<Result<Vec<Scalar>, _>>()?;

		// The scalar set size should be equal to the maximum number of participants
		if scalar_set.len() < NUM_NEIGHBOURS {
			scalar_set.resize(NUM_NEIGHBOURS, Scalar::zero());
		}

		// Setup circuit ECDSA public keys vector
		let mut ecdsa_pub_keys: Vec<Option<ECDSAPublicKey>> = Vec::with_capacity(NUM_NEIGHBOURS);
		for index in 0..NUM_NEIGHBOURS {
			let key = if index < address_set.len() {
				pub_key_map.get(&address_set[index]).cloned()
			} else {
				None
			};

			ecdsa_pub_keys.push(key);
		}

		// Initialize attestation matrix
		let mut attestation_matrix: Vec<OpinionVector> =
			vec![vec![None; NUM_NEIGHBOURS]; NUM_NEIGHBOURS];

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
		for i in 0..address_set.len() {
			native_et.add_member(scalar_set[i]);
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

		// Generate opinions' sponge hash.
		let mut sponge = PoseidonNativeSponge::new();
		sponge.update(&op_hashes);
		let opinions_hash = sponge.squeeze();

		// Build public inputs
		let pub_inputs =
			ETPublicInputs::new(scalar_set, scalar_scores, scalar_domain, opinions_hash);

		Ok(ETSetup::new(
			address_set, attestation_matrix, ecdsa_pub_keys, pub_inputs, rational_scores,
		))
	}

	/// Generates Threshold circuit proof for the selected participant
	pub fn th_circuit_setup(
		&self, att: Vec<SignedAttestationRaw>, raw_et_kzg_params: Vec<u8>, threshold: u32,
		participant: [u8; 20],
	) -> Result<ThSetup, EigenError> {
		let rng = &mut thread_rng();
		let et_setup = self.et_circuit_setup(att)?;

		// Build kzg params and proving key
		let et_kzg_params =
			ParamsKZG::<Bn256>::read(&mut raw_et_kzg_params.as_slice()).map_err(|e| {
				EigenError::ReadWriteError(format!("Failed to read ET KZG params: {}", e))
			})?;

		// Find participant in the set and get the id
		let participant_address = Address::from(participant);
		let id = et_setup.address_set.iter().position(|r| r == &participant_address).ok_or_else(
			|| {
				EigenError::ValidationError(format!(
					"Participant {} not found",
					participant_address.to_string()
				))
			},
		)?;

		// Extract and prepare participant-specific data
		let p_address = et_setup.pub_inputs.participants[id];
		let score = et_setup.pub_inputs.scores[id];
		let rational_score = et_setup.rational_scores[id].clone();
		let (scalar_num, scalar_den) =
			big_to_fe_rat::<Scalar, NUM_DECIMAL_LIMBS, POWER_OF_TEN>(rational_score.clone());

		// Check native threshold circuit
		let scalar_th = Scalar::from(u64::from(threshold));
		let native_th = NativeThreshold4::new(score, rational_score, scalar_th);
		let native_th_check = if native_th.check_threshold() { Scalar::ONE } else { Scalar::ZERO };

		// Setup EigenTrust and Aggregator circuits
		let et_circuit = EigenTrust4::new(
			et_setup.attestation_matrix,
			et_setup.ecdsa_set,
			self.get_scalar_domain()?,
		);
		let snark = Snark::new(
			&et_kzg_params,
			et_circuit,
			vec![et_setup.pub_inputs.to_vec()],
			rng,
		);
		let native_agg = NativeAggregator4::new(&et_kzg_params, vec![snark]);

		// Setup Threshold circuit public inputs
		let th_pub_inp = ThPublicInputs::new(
			p_address,
			scalar_th,
			native_th_check,
			native_agg.instances.clone(),
		);

		// Build Threshold circuit
		let th_circuit = Threshold4::new::<PoseidonNativeSponge>(
			&et_setup.pub_inputs.participants, &et_setup.pub_inputs.scores, &scalar_num,
			&scalar_den, native_agg.svk, native_agg.snarks, native_agg.as_proof,
		);

		Ok(ThSetup::new(th_circuit, th_pub_inp))
	}

	/// Generates new proving key for EigenTrust circuit
	pub fn generate_et_pk(raw_kzg_params: Vec<u8>) -> Result<Vec<u8>, EigenError> {
		let rng = &mut rand::thread_rng();

		let opt_att = vec![vec![None; NUM_ITERATIONS]; NUM_ITERATIONS];
		let opt_pks = vec![None; NUM_ITERATIONS];
		let domain = Scalar::random(rng);
		let et = EigenTrust4::new(opt_att, opt_pks, domain);

		let kzg_params = ParamsKZG::<Bn256>::read(&mut raw_kzg_params.as_slice())
			.map_err(|e| EigenError::ReadWriteError(format!("Failed to read KZG params: {}", e)))?;

		info!("Generating proving key, this may take a while.");
		let start_time = Instant::now();
		let proving_key = keygen(&kzg_params, et)
			.map_err(|_| EigenError::KeygenError("Failed to generate pk/vk pair".to_string()))?;
		let elapsed_time = start_time.elapsed();

		info!("Proving key generated.");
		debug!("Proving key generation time: {:?}", elapsed_time);

		Ok(proving_key.to_bytes(SerdeFormat::Processed))
	}

	/// Generates new proving key for the Threshold circuit
	pub fn generate_th_pk(
		&self, att: Vec<SignedAttestationRaw>, raw_et_kzg_params: Vec<u8>,
		raw_th_kzg_params: Vec<u8>,
	) -> Result<Vec<u8>, EigenError> {
		let th_kzg_params =
			ParamsKZG::<Bn256>::read(&mut raw_th_kzg_params.as_slice()).map_err(|e| {
				EigenError::ReadWriteError(format!("Failed to read TH KZG params: {}", e))
			})?;
		let participant = AttestationEth::from(att[0].clone().attestation).about.to_fixed_bytes();
		let th_setup =
			self.th_circuit_setup(att, raw_et_kzg_params, u32::default(), participant)?;

		info!("Generating proving key, this may take a while.");
		let start_time = Instant::now();

		let proving_key = keygen(&th_kzg_params, th_setup.circuit).map_err(|e| {
			EigenError::KeygenError(format!("Failed to generate pk/vk pair: {}", e))
		})?;

		let elapsed_time = start_time.elapsed();
		info!("Proving key generated.");
		debug!("Proving key generation time: {:?}", elapsed_time);

		Ok(proving_key.to_bytes(SerdeFormat::Processed))
	}

	/// Generates new KZG params (Mostly used for testing)
	pub fn generate_kzg_params(k: u32) -> Result<Vec<u8>, EigenError> {
		info!("Generating KZG parameters, this may take a while.");

		let start_time = Instant::now();
		let params = generate_params::<Bn256>(k);
		let elapsed_time = start_time.elapsed();

		info!("KZG parameters generated.");
		debug!("KZG parameters generation time: {:?}", elapsed_time);

		let mut buffer: Vec<u8> = Vec::new();
		params.write(&mut buffer).map_err(|e| {
			EigenError::ReadWriteError(format!("Failed to write KZG parameters: {}", e))
		})?;

		Ok(buffer)
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

	/// Fetches "AttestationCreated" event logs from the contract, filtered by domain.
	pub async fn get_logs(&self) -> Result<Vec<Log>, EigenError> {
		let as_contract = AttestationStation::new(self.as_address, self.get_signer());

		// Set filter
		let filter = as_contract
			.attestation_created_filter()
			.filter
			.topic3(build_att_key(self.domain))
			.from_block(0);

		// Fetch logs matching the filter.
		self.signer.get_logs(&filter).await.map_err(|e| EigenError::ParsingError(e.to_string()))
	}

	/// Gets the domain as BN256 scalar.
	pub fn get_scalar_domain(&self) -> Result<Scalar, EigenError> {
		let domain_bytes_256 = H256::from(self.domain);

		let mut domain = *domain_bytes_256.as_fixed_bytes();
		domain.reverse();

		let domain_opt = Scalar::from_bytes(&domain);

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

		let th_circuit: NativeThreshold4 = Threshold::new(score_fr, score_ratio, threshold_fr);

		th_circuit.check_threshold()
	}
}

#[cfg(test)]
mod lib_tests {
	use crate::{
		att_station::AttestationStation,
		attestation::{AttestationRaw, DOMAIN_PREFIX, DOMAIN_PREFIX_LEN},
		eth::deploy_as,
		Client, ContractAttestationData,
	};
	use ethers::{
		types::{Address, Bytes, H160},
		utils::Anvil,
	};
	use std::str::FromStr;

	const TEST_MNEMONIC: &'static str =
		"test test test test test test test test test test test junk";
	const TEST_AS_ADDRESS: &'static str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
	const TEST_CHAIN_ID: u32 = 31337;

	#[tokio::test]
	async fn test_attest() {
		let anvil = Anvil::new().spawn();
		let node_url = anvil.endpoint().to_string();
		let client = Client::new(
			TEST_MNEMONIC.to_string(),
			TEST_CHAIN_ID,
			Address::from_str(TEST_AS_ADDRESS).unwrap().to_fixed_bytes(),
			H160::zero().to_fixed_bytes(),
			node_url.clone(),
		);

		// Deploy attestation station
		let as_address = deploy_as(client.get_signer()).await.unwrap();

		// Update client with new addresses
		let updated_client = Client::new(
			TEST_MNEMONIC.to_string(),
			TEST_CHAIN_ID,
			as_address.to_fixed_bytes(),
			H160::zero().to_fixed_bytes(),
			node_url,
		);

		// Attest
		let attestation = AttestationRaw::new([0; 20], [0; 20], 5, [0; 32]);
		assert!(updated_client.attest(attestation).await.is_ok());

		drop(anvil);
	}

	#[tokio::test]
	async fn test_get_attestations() {
		let anvil = Anvil::new().spawn();
		let node_url = anvil.endpoint().to_string();

		// Build domain
		let domain_input = [
			0xff, 0x61, 0x4a, 0x6d, 0x59, 0x56, 0x2a, 0x42, 0x37, 0x72, 0x37, 0x76, 0x32, 0x4d,
			0x36, 0x53, 0x62, 0x6d, 0x35, 0xff,
		];

		let client = Client::new(
			TEST_MNEMONIC.to_string(),
			TEST_CHAIN_ID,
			Address::from_str(TEST_AS_ADDRESS).unwrap().to_fixed_bytes(),
			domain_input,
			node_url.clone(),
		);

		// Deploy attestation station
		let as_address = deploy_as(client.get_signer()).await.unwrap();

		// Update config with new addresses and instantiate client
		let client = Client::new(
			TEST_MNEMONIC.to_string(),
			TEST_CHAIN_ID,
			as_address.to_fixed_bytes(),
			domain_input,
			node_url,
		);

		// Build Attestation
		let about_bytes = [
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

	#[tokio::test]
	async fn test_get_logs() {
		let anvil = Anvil::new().spawn();
		let node_url = anvil.endpoint().to_string();
		let client = Client::new(
			TEST_MNEMONIC.to_string(),
			TEST_CHAIN_ID,
			Address::from_str(TEST_AS_ADDRESS).unwrap().to_fixed_bytes(),
			H160::zero().to_fixed_bytes(),
			node_url.clone(),
		);

		// Deploy attestation station
		let as_address = deploy_as(client.get_signer()).await.unwrap();

		// Update config with new addresses and instantiate client
		let updated_client = Client::new(
			TEST_MNEMONIC.to_string(),
			TEST_CHAIN_ID,
			as_address.to_fixed_bytes(),
			H160::zero().to_fixed_bytes(),
			node_url,
		);

		// Submit a good attestation
		let good_attestation = AttestationRaw::new([0; 20], [0; 20], 5, [0; 32]);
		updated_client.attest(good_attestation).await.unwrap();

		let as_contract = AttestationStation::new(as_address, client.get_signer());

		// Submit a bad attestation
		let contract_data = ContractAttestationData {
			about: Address::zero(),
			key: [0; 32],
			val: Bytes("0x0".into()),
		};
		let tx_call = as_contract.attest(vec![contract_data]);
		tx_call.send().await.unwrap();

		// Fetch logs
		let fetched_logs = updated_client.get_logs().await.unwrap();

		// Asserts
		assert_eq!(fetched_logs.len(), 1);
		let prefix_in_fetched_log =
			&fetched_logs[0].topics[3].as_fixed_bytes()[..DOMAIN_PREFIX_LEN];
		assert_eq!(prefix_in_fetched_log, DOMAIN_PREFIX);

		drop(anvil);
	}
}
