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
pub mod utils;

use crate::att_station::AttestationCreatedFilter;
use att_station::{AttestationData as ContractAttestationData, AttestationStation as AttStation};
use attestation::{Attestation, AttestationPayload, SignedAttestation};
use eigen_trust_circuit::{
	dynamic_sets::native::{EigenTrustSet, Opinion},
	eddsa::native::{sign, PublicKey, Signature},
	halo2::halo2curves::bn256::Fr as Scalar,
};
use error::EigenError;
use ethers::{
	abi::{Address, RawLog},
	contract::EthEvent,
	prelude::EthDisplay,
	providers::Middleware,
	signers::Signer,
	types::{Filter, H256},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utils::{
	ecdsa_eddsa_map, eddsa_sk_from_mnemonic, eth_wallets_from_mnemonic, setup_client,
	SignerMiddlewareArc,
};

/// Max amount of participants
const MAX_NEIGHBOURS: usize = 2;
/// Number of iterations to run the eigen trust algorithm
const NUM_ITERATIONS: usize = 10;
/// Initial score for each participant before the algorithms is run
const INITIAL_SCORE: u128 = 1000;
/// Scale for the scores to be computed inside the ZK circuit
const SCALE: u128 = 1000;

#[derive(Serialize, Deserialize, Debug, EthDisplay, Clone)]
pub struct ClientConfig {
	pub as_address: String,
	pub et_verifier_wrapper_address: String,
	pub mnemonic: String,
	pub node_url: String,
}

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
		let sk_vec = eddsa_sk_from_mnemonic(&self.config.mnemonic, 1).unwrap();
		let wallets = eth_wallets_from_mnemonic(&self.config.mnemonic, 1).unwrap();

		// User keys
		let user_address = wallets[0].address();
		let user_sk = &sk_vec[0];

		let signature = sign(user_sk, &user_sk.public(), Scalar::from(&attestation));

		let signed_attestation = SignedAttestation::new(attestation, user_address, signature);

		let as_address_res = self.config.as_address.parse::<Address>();
		let as_address = as_address_res.map_err(|_| EigenError::ParseError)?;
		let as_contract = AttStation::new(as_address, self.client.clone());

		let tx_call = as_contract.attest(vec![ContractAttestationData::from(signed_attestation)]);
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
		// Get attestations
		let signed_attestations = self.get_signed_attestations().await.unwrap();

		// Asume unique key
		// TODO: Update function to map all attestation keys

		// Get participants (attesters and attested)
		let mut participants_map = HashMap::<Address, ()>::new();
		for att in signed_attestations.clone() {
			participants_map.insert(att.attestation.about, ());
			participants_map.insert(att.attester, ());
		}
		let participants: Vec<Address> = participants_map.keys().cloned().collect();

		// Get EDDSA public keys
		// Temporary, in future implementations we'll recover the ecdsa public key from the transaction signature
		let address_map: HashMap<Address, PublicKey> = ecdsa_eddsa_map(&self.config.mnemonic);
		let eddsa_pub_keys: Vec<PublicKey> =
			participants.iter().map(|participant| *address_map.get(participant).unwrap()).collect();

		// Create a HashMap for quick lookup of attestations by attester and attested
		let mut attestation_map: HashMap<(Address, Address), SignedAttestation> = HashMap::new();
		for attestation in signed_attestations.iter() {
			let attester = attestation.attester;
			let attested_address = attestation.attestation.about;
			attestation_map.insert((attester, attested_address), attestation.clone());
		}

		// Get scores
		let mut scores: Vec<Vec<Scalar>> = Vec::new();

		for attester in &participants {
			let mut current_scores: Vec<Scalar> = Vec::new();

			for attested in &participants {
				let score = if attester == attested {
					Scalar::zero()
				} else {
					match attestation_map.get(&(*attester, *attested)) {
						Some(attestation) => Scalar::from(attestation.attestation.value as u64),
						None => Scalar::zero(),
					}
				};

				current_scores.push(score);
			}

			scores.push(current_scores);
		}

		println!("Scores: {:?}", scores);

		// Construct native set
		let mut eigentrust_set =
			EigenTrustSet::<MAX_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE, SCALE>::new();

		// Add eddsa public keys to the set
		for pub_key in eddsa_pub_keys.clone() {
			eigentrust_set.add_member(pub_key);
		}

		// Update opinions in the set
		for i in 0..participants.len() {
			let attester = &participants[i];
			let attester_pub_key = address_map.get(attester).unwrap();

			// Create an array for the Opinion scores
			let opinion_array = eddsa_pub_keys
				.iter()
				.zip(&scores[i])
				.map(|(pub_key, score)| (*pub_key, *score))
				.collect::<Vec<(PublicKey, Scalar)>>();

			let opinion =
				Opinion::<MAX_NEIGHBOURS>::new(Signature::default(), Scalar::zero(), opinion_array);

			eigentrust_set.update_op(*attester_pub_key, opinion);
		}

		// Converge the EigenTrust scores
		let (scores, scores_scaled) = eigentrust_set.converge();

		println!("Scores: {:?}", scores);
		println!("Scores scaled: {:?}", scores_scaled);

		// TODO: Write the resulting scores to a CSV file

		Ok(())
	}

	/// Get the attestations from the contract
	pub async fn get_signed_attestations(&self) -> Result<Vec<SignedAttestation>, EigenError> {
		let filter = Filter::new()
			.address(self.config.as_address.parse::<Address>().unwrap())
			.event("AttestationCreated(address,address,bytes32,bytes)")
			.topic1(Vec::<H256>::new())
			.topic2(Vec::<H256>::new())
			.from_block(0);
		let logs = &self.client.get_logs(&filter).await.unwrap();
		let mut signed = Vec::new();

		println!("Indexed attestations: {}", logs.iter().len());

		for log in logs.iter() {
			let raw_log = RawLog::from((log.topics.clone(), log.data.to_vec()));
			let att_created = AttestationCreatedFilter::decode_log(&raw_log).unwrap();
			let att_data =
				AttestationPayload::from_bytes(att_created.val.to_vec()).expect("Failed to decode");

			let att = Attestation::new(
				att_created.about,
				att_created.key,
				att_data.get_value(),
				Some(att_data.get_message()),
			);

			let signed_attestation =
				SignedAttestation::new(att, att_created.creator, att_data.get_signature());

			signed.push(signed_attestation);
		}

		// TODO: For future impl, reconstruct ECDSA public keys from transaction signature

		Ok(signed)
	}

	/// Verifies last generated proof
	pub async fn verify(&self) -> Result<(), EigenError> {
		// TODO: Verify proof
		Ok(())
	}
}

#[cfg(test)]
mod lib_tests {
	use crate::{
		attestation::Attestation,
		utils::{deploy_as, deploy_verifier, eth_wallets_from_mnemonic},
		Client, ClientConfig,
	};
	use eigen_trust_circuit::utils::read_bytes_data;
	use ethers::signers::Signer;
	use ethers::utils::Anvil;

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

		let attestation = Attestation::new(
			eth_wallets_from_mnemonic(&mnemonic, 2).unwrap()[1].address(),
			[0; 32],
			1,
			None,
		);

		assert!(Client::new(config).attest(attestation).await.is_ok());

		drop(anvil);
	}
}
