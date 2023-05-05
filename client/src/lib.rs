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

#[derive(Debug)]
pub enum ClientError {
	DecodeError,
	ParseError,
	TxError,
}

#[derive(Serialize, Deserialize, Debug, EthDisplay, Clone)]
pub struct ClientConfig {
	pub ops: Vec<u8>,
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
	pub async fn attest(&self) -> Result<(), ClientError> {
		let sk_vec = eddsa_sk_from_mnemonic(&self.config.mnemonic, 2).unwrap();
		let wallets = eth_wallets_from_mnemonic(&self.config.mnemonic, 2).unwrap();

		// User keys
		let user_address = wallets[0].address();
		let user_sk = &sk_vec[0];

		// Attest for neighbour 1
		let neighbour_score = self.config.ops[1];
		let neighbour_address = wallets[1].address();

		let attestation = Attestation::new(neighbour_address, [0; 32], neighbour_score, None);

		let signature = sign(user_sk, &user_sk.public(), Scalar::from(&attestation));

		let signed_attestation = SignedAttestation::new(attestation, user_address, signature);

		let as_address_res = self.config.as_address.parse::<Address>();
		let as_address = as_address_res.map_err(|_| ClientError::ParseError)?;
		let as_contract = AttStation::new(as_address, self.client.clone());

		let tx_call = as_contract.attest(vec![ContractAttestationData::from(signed_attestation)]);
		let tx_res = tx_call.send();
		let tx = tx_res.await.map_err(|_| ClientError::TxError)?;
		let res = tx.await.map_err(|_| ClientError::TxError)?;

		if let Some(receipt) = res {
			println!("Transaction status: {:?}", receipt.status);
		}

		Ok(())
	}

	/// Calculate proofs
	pub async fn calculate_proofs(&mut self) -> Result<(), EigenError> {
		// Get attestations
		let signed_attestations = self.get_signed_attestations().await.unwrap();

		// Asume unique key -> [0;32]
		// TODO: Update function to map all attestation keys

		// Get all participants
		let mut participants_map = HashMap::<Address, ()>::new();

		for att in signed_attestations.clone() {
			// Insert attested
			participants_map.insert(att.attestation.about, ());

			// Insert attester
			participants_map.insert(att.attester, ());
		}

		// Create participants vector
		let participants: Vec<Address> = participants_map.keys().cloned().collect();

		// Create eddsa public keys vector
		let mut eddsa_pub_keys: Vec<PublicKey> = Vec::new();

		// Get address map
		// Temporary, in future implementations we'll recover the ecdsa public key from the transaction signature
		let address_map = ecdsa_eddsa_map(&self.config.mnemonic);

		for participant in participants.clone() {
			eddsa_pub_keys.push(*address_map.get(&participant).unwrap());
		}

		// Create signatures vector
		// Temporary - Still based on multiple attestation format
		let mut signatures: Vec<Signature> = Vec::new();

		for _ in 0..participants.len() {
			signatures.push(Signature::default());
		}

		// Create opinion public keys and scores vectors
		let mut attested_pub_keys: Vec<Vec<PublicKey>> = Vec::new();
		let mut scores: Vec<Vec<Scalar>> = Vec::new();

		// Group attestations by attester
		let mut attester_groups: HashMap<Address, Vec<SignedAttestation>> = HashMap::new();
		for attestation in signed_attestations.iter() {
			attester_groups
				.entry(attestation.attester)
				.or_insert_with(Vec::new)
				.push(attestation.clone());
		}

		// Iterate through attester groups and fill attested_pub_keys and scores vectors
		for (_attester, attestations) in attester_groups {
			let mut current_attested_pub_keys: Vec<PublicKey> = Vec::new();
			let mut current_scores: Vec<Scalar> = Vec::new();

			for attestation in attestations {
				let attested_address = attestation.attestation.about;
				let attested_pub_key = *address_map.get(&attested_address).unwrap();
				let score = Scalar::from(attestation.attestation.value as u64);

				current_attested_pub_keys.push(attested_pub_key);
				current_scores.push(score);
			}

			attested_pub_keys.push(current_attested_pub_keys);
			scores.push(current_scores);
		}

		// Construct native set
		let mut eigentrust_set = EigenTrustSet::new();

		// Add eddsa public keys to the set
		for pub_key in eddsa_pub_keys {
			eigentrust_set.add_member(pub_key);
		}

		// Update opinions in the set
		for i in 0..participants.len() {
			let attester = &participants[i];
			let attester_pub_key = address_map.get(attester).unwrap();

			// Create an array for the Opinion scores
			let opinion_array = attested_pub_keys[i]
				.iter()
				.zip(&scores[i])
				.map(|(pub_key, score)| (*pub_key, *score))
				.collect::<Vec<(PublicKey, Scalar)>>();

			// Convert the Vec into an array [(PublicKey, Scalar); 5]
			let opinion_scores: [(PublicKey, Scalar); 5] =
				opinion_array.try_into().expect("Failed to convert the Vec into an array");

			// Create an Opinion
			let opinion = Opinion {
				sig: Signature::default(),
				message_hash: Scalar::zero(),
				scores: opinion_scores,
			};

			eigentrust_set.update_op(*attester_pub_key, opinion);
		}

		// Converge the EigenTrust scores
		eigentrust_set.converge();

		// TODO: Store proofs

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
	pub async fn verify(&self) -> Result<(), ClientError> {
		// TODO: Verify proof
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use crate::{
		utils::{deploy_as, deploy_verifier},
		Client, ClientConfig,
	};
	use eigen_trust_circuit::utils::read_bytes_data;
	use ethers::utils::Anvil;

	#[tokio::test]
	async fn should_add_attestation() {
		let anvil = Anvil::new().spawn();
		let mnemonic = "test test test test test test test test test test test junk".to_string();
		let node_url = anvil.endpoint();
		let as_address = deploy_as(&mnemonic, &node_url).await.unwrap();
		let et_contract = read_bytes_data("et_verifier");
		let et_verifier_address = deploy_verifier(&mnemonic, &node_url, et_contract).await.unwrap();
		let as_address_string = format!("{:?}", as_address);
		let et_verifier_address_string = format!("{:?}", et_verifier_address);

		let config = ClientConfig {
			ops: vec![4, 4],
			as_address: as_address_string,
			et_verifier_wrapper_address: et_verifier_address_string,
			mnemonic,
			node_url,
		};

		let et_client = Client::new(config);
		let res = et_client.attest().await;
		assert!(res.is_ok());

		drop(anvil);
	}
}
