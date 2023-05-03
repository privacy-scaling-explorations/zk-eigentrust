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
	calculate_message_hash,
	eddsa::native::{sign, PublicKey},
	halo2::{
		halo2curves::bn256::{Bn256, Fr as Scalar, G1Affine},
		plonk::ProvingKey,
		poly::kzg::commitment::ParamsKZG,
	},
	ProofRaw,
};
use error::EigenError;
use ethers::{
	abi::{Address, RawLog},
	contract::EthEvent,
	prelude::EthDisplay,
	providers::Middleware,
	signers::Signer,
	types::{Bytes, Filter, H256, U256},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utils::{
	ecdsa_eddsa_map, eddsa_sk_from_mnemonic, eth_wallets_from_mnemonic, setup_client,
	EtVerifierWrapper, SignerMiddlewareArc,
};

/// Number of iterations to run the eigen trust algorithm
pub const NUM_ITER: usize = 10;
/// Numbers of participants
pub const NUM_NEIGHBOURS: usize = 5;
/// Initial score for each participant before the algorithms is run
pub const INITIAL_SCORE: u128 = 1000;
/// Scale for the scores to be computed inside the ZK circuit
pub const SCALE: u128 = 1000;

#[derive(Debug)]
pub enum ClientError {
	DecodeError,
	ParseError,
	TxError,
}

#[derive(Serialize, Deserialize, Debug, EthDisplay, Clone)]
pub struct ClientConfig {
	pub ops: [u8; NUM_NEIGHBOURS],
	pub secret_key: [String; 2],
	pub as_address: String,
	pub et_verifier_wrapper_address: String,
	pub mnemonic: String,
	pub node_url: String,
}

pub struct Client {
	client: SignerMiddlewareArc,
	config: ClientConfig,
	params: ParamsKZG<Bn256>,
	proving_key: ProvingKey<G1Affine>,
}

impl Client {
	/// Create a new client
	pub fn new(config: ClientConfig, params: ParamsKZG<Bn256>, pk: ProvingKey<G1Affine>) -> Self {
		let client = setup_client(&config.mnemonic, &config.node_url);
		Self { client, config, params, proving_key: pk }
	}

	/// Submit an attestation to the attestation station
	pub async fn attest(&self) -> Result<(), ClientError> {
		let sk_vec = eddsa_sk_from_mnemonic(&self.config.mnemonic, 2).unwrap();
		let wallets = eth_wallets_from_mnemonic(&self.config.mnemonic, 2).unwrap();

		// User keys
		let user_sk = &sk_vec[0];

		// Attest for neighbour 1
		let neighbour_score = self.config.ops[1];
		let neighbour_address = wallets[1].address();

		let attestation = Attestation::new(neighbour_address, [0; 32], neighbour_score, None);

		let (_, message_hash) = calculate_message_hash::<1, 1>(
			vec![user_sk.public()],
			vec![vec![Scalar::from(neighbour_score as u64)]],
		);

		let signature = sign(user_sk, &user_sk.public(), message_hash[0]);

		let signed_attestation =
			SignedAttestation::new(attestation, wallets[0].address(), signature);

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
		// Get participants
		let signed_attestations = self.get_signed_attestations().await.unwrap();

		let mut participants_map = HashMap::<Address, ()>::new();

		for att in signed_attestations {
			// Insert attested
			participants_map.insert(att.attestation.about, ());

			// Insert attester
			participants_map.insert(att.attester, ());
		}

		let participants: Vec<Address> = participants_map.keys().cloned().collect();

		// Get address map
		let address_map = ecdsa_eddsa_map(&self.config.mnemonic);

		// Pair addresses
		let mut address_pairs: Vec<(Address, PublicKey)> = Vec::new();

		for participant in participants {
			address_pairs.push((participant, *address_map.get(&participant).unwrap()));
		}

		// Generate initial attestations for each participant

		// TODO: Use dynamic set

		// TODO: Store proofs

		Ok(())
	}

	/// Generate initial attestations for all participants in the set
	pub fn generate_initial_attestations(&mut self) {
		// TODO
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

		Ok(signed)
	}

	/// Verifies last generated proof
	pub async fn verify(&self) -> Result<(), ClientError> {
		// let addr_res = self.config.et_verifier_wrapper_address.parse::<Address>();
		// let addr = addr_res.map_err(|_| ClientError::ParseError)?;
		// let et_wrapper_contract = EtVerifierWrapper::new(addr, self.client.clone());

		// let mut pub_ins = [U256::default(); NUM_NEIGHBOURS];
		// for (i, x) in proof_raw.pub_ins.iter().enumerate() {
		// 	pub_ins[i] = U256::from(x);
		// }
		// let proof_bytes = Bytes::from(proof_raw.proof.clone());

		// let tx_call = et_wrapper_contract.verify(pub_ins, proof_bytes);
		// let tx_res = tx_call.send();
		// let tx = tx_res.await.map_err(|e| {
		// 	eprintln!("{:?}", e);
		// 	ClientError::TxError
		// })?;
		// let res = tx.await.map_err(|e| {
		// 	eprintln!("{:?}", e);
		// 	ClientError::TxError
		// })?;

		// if let Some(receipt) = res {
		// 	println!("Transaction status: {:?}", receipt.status);
		// }

		Ok(())
	}
}

#[cfg(test)]
mod test {
	// use crate::{
	// 	manager::NUM_NEIGHBOURS,
	// 	utils::{deploy_as, deploy_et_wrapper, deploy_verifier},
	// 	Client, ClientConfig,
	// };
	// use eigen_trust_circuit::{
	// 	utils::{read_bytes_data, read_json_data},
	// 	ProofRaw,
	// };
	// use ethers::{abi::Address, utils::Anvil};

	// #[tokio::test]
	// async fn should_add_attestation() {
	// 	let anvil = Anvil::new().spawn();
	// 	let mnemonic = "test test test test test test test test test test test junk".to_string();
	// 	let node_url = anvil.endpoint();
	// 	let as_address = deploy_as(&mnemonic, &node_url).await.unwrap();
	// 	let et_contract = read_bytes_data("et_verifier");
	// 	let et_verifier_address = deploy_verifier(&mnemonic, &node_url, et_contract).await.unwrap();
	// 	let as_address_string = format!("{:?}", as_address);
	// 	let et_verifier_address_string = format!("{:?}", et_verifier_address);

	// 	let dummy_user = [
	// 		"Alice".to_string(),
	// 		"2L9bbXNEayuRMMbrWFynPtgkrXH1iBdfryRH9Soa8M67".to_string(),
	// 		"9rBeBVtbN2MkHDTpeAouqkMWNFJC6Bxb6bXH9jUueWaF".to_string(),
	// 	];
	// 	let user_secrets_raw = vec![dummy_user; NUM_NEIGHBOURS];

	// 	let config = ClientConfig {
	// 		ops: [200, 200, 200, 200, 200],
	// 		secret_key: [
	// 			"2L9bbXNEayuRMMbrWFynPtgkrXH1iBdfryRH9Soa8M67".to_string(),
	// 			"9rBeBVtbN2MkHDTpeAouqkMWNFJC6Bxb6bXH9jUueWaF".to_string(),
	// 		],
	// 		as_address: as_address_string,
	// 		et_verifier_wrapper_address: et_verifier_address_string,
	// 		mnemonic,
	// 		node_url,
	// 	};

	// 	let et_client = Client::new(config);
	// 	let res = et_client.attest().await;
	// 	assert!(res.is_ok());

	// 	drop(anvil);
	// }

	// #[tokio::test]
	// async fn should_verify_proof() {
	// 	let anvil = Anvil::new().spawn();
	// 	let mnemonic = "test test test test test test test test test test test junk".to_string();
	// 	let node_url = anvil.endpoint();
	// 	let et_contract = read_bytes_data("et_verifier");
	// 	let et_verifier_address = deploy_verifier(&mnemonic, &node_url, et_contract).await.unwrap();
	// 	let et_verifier_wr =
	// 		deploy_et_wrapper(&mnemonic, &node_url, et_verifier_address).await.unwrap();
	// 	let et_verifier_address_string = format!("{:?}", et_verifier_wr);

	// 	let dummy_user = [
	// 		"Alice".to_string(),
	// 		"2L9bbXNEayuRMMbrWFynPtgkrXH1iBdfryRH9Soa8M67".to_string(),
	// 		"9rBeBVtbN2MkHDTpeAouqkMWNFJC6Bxb6bXH9jUueWaF".to_string(),
	// 	];
	// 	let user_secrets_raw = vec![dummy_user; NUM_NEIGHBOURS];

	// 	let config = ClientConfig {
	// 		ops: [200, 200, 200, 200, 200],
	// 		secret_key: [
	// 			"2L9bbXNEayuRMMbrWFynPtgkrXH1iBdfryRH9Soa8M67".to_string(),
	// 			"9rBeBVtbN2MkHDTpeAouqkMWNFJC6Bxb6bXH9jUueWaF".to_string(),
	// 		],
	// 		as_address: format!("{:?}", Address::default()),
	// 		et_verifier_wrapper_address: et_verifier_address_string,
	// 		mnemonic,
	// 		node_url,
	// 	};

	// 	let et_client = Client::new(config);
	// 	let proof_raw: ProofRaw = read_json_data("et_proof").unwrap();
	// 	let res = et_client.verify(proof_raw).await;
	// 	assert!(res.is_ok());

	// 	drop(anvil);
	// }
}
