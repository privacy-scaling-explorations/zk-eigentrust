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
pub mod manager;
pub mod utils;

use crate::manager::NUM_NEIGHBOURS;
use att_station::{AttestationData as AttData, AttestationStation as AttStation};
use attestation::{Attestation, AttestationData};
use eigen_trust_circuit::{
	calculate_message_hash,
	eddsa::native::{sign, SecretKey},
	halo2::halo2curves::{bn256::Fr as Scalar, FieldExt},
	utils::to_short,
	ProofRaw,
};
use ethers::{
	abi::Address,
	prelude::EthDisplay,
	types::{Bytes, U256},
};
use serde::{Deserialize, Serialize};
use utils::{setup_client, EtVerifierWrapper, SignerMiddlewareArc};

#[derive(Debug)]
pub enum ClientError {
	DecodeError,
	ParseError,
	TxError,
}

#[derive(Serialize, Deserialize, Debug, EthDisplay, Clone)]
pub struct ClientConfig {
	pub ops: [u128; NUM_NEIGHBOURS],
	pub secret_key: [String; 2],
	pub as_address: String,
	pub et_verifier_wrapper_address: String,
	pub mnemonic: String,
	pub ethereum_node_url: String,
}

pub struct Client {
	client: SignerMiddlewareArc,
	config: ClientConfig,
	user_secrets_raw: Vec<[String; 3]>,
}

impl Client {
	pub fn new(config: ClientConfig, user_secrets_raw: Vec<[String; 3]>) -> Self {
		let client = setup_client(&config.mnemonic, &config.ethereum_node_url);
		Self { client, config, user_secrets_raw }
	}

	pub async fn attest(&self) -> Result<(), ClientError> {
		let mut sk_vec = Vec::new();
		for x in &self.user_secrets_raw {
			let sk0_decoded_bytes = bs58::decode(&x[1]).into_vec();
			let sk1_decoded_bytes = bs58::decode(&x[2]).into_vec();

			let sk0_decoded = sk0_decoded_bytes.map_err(|_| ClientError::DecodeError)?;
			let sk1_decoded = sk1_decoded_bytes.map_err(|_| ClientError::DecodeError)?;

			let sk0 = to_short(&sk0_decoded);
			let sk1 = to_short(&sk1_decoded);
			let sk = SecretKey::from_raw([sk0, sk1]);
			sk_vec.push(sk);
		}

		let user_secrets: [SecretKey; NUM_NEIGHBOURS] =
			sk_vec.try_into().map_err(|_| ClientError::DecodeError)?;
		let user_publics = user_secrets.map(|s| s.public());

		let sk0_bytes_vec = bs58::decode(&self.config.secret_key[0]).into_vec();
		let sk1_bytes_vec = bs58::decode(&self.config.secret_key[1]).into_vec();

		let sk0_bytes = sk0_bytes_vec.map_err(|_| ClientError::DecodeError)?;
		let sk1_bytes = sk1_bytes_vec.map_err(|_| ClientError::DecodeError)?;

		let mut sk0: [u8; 32] = [0; 32];
		sk0[..].copy_from_slice(&sk0_bytes);

		let mut sk1: [u8; 32] = [0; 32];
		sk1[..].copy_from_slice(&sk1_bytes);

		let sk = SecretKey::from_raw([sk0, sk1]);
		let pk = sk.public();

		let ops = self.config.ops.map(Scalar::from_u128);

		let (pks_hash, message_hash) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(user_publics.to_vec(), vec![ops.to_vec()]);

		let sig = sign(&sk, &pk, message_hash[0]);

		let att = Attestation::new(sig, pk, user_publics.to_vec(), ops.to_vec());
		let att_data = AttestationData::from(att);
		let bytes = att_data.to_bytes();

		let as_address_res = self.config.as_address.parse::<Address>();
		let as_address = as_address_res.map_err(|_| ClientError::ParseError)?;
		let as_contract = AttStation::new(as_address, self.client.clone());

		let as_data = AttData(
			Address::zero(),
			pks_hash.to_bytes(),
			Bytes::from(bytes.clone()),
		);
		let as_data_vec = vec![as_data];

		let tx_call = as_contract.attest(as_data_vec);
		let tx_res = tx_call.send();
		let tx = tx_res.await.map_err(|_| ClientError::TxError)?;
		let res = tx.await.map_err(|_| ClientError::TxError)?;

		if let Some(receipt) = res {
			println!("Transaction status: {:?}", receipt.status);
		}

		Ok(())
	}

	pub async fn verify(&self, proof_raw: ProofRaw) -> Result<(), ClientError> {
		let addr_res = self.config.et_verifier_wrapper_address.parse::<Address>();
		let addr = addr_res.map_err(|_| ClientError::ParseError)?;
		let et_wrapper_contract = EtVerifierWrapper::new(addr, self.client.clone());

		let mut pub_ins = [U256::default(); NUM_NEIGHBOURS];
		for (i, x) in proof_raw.pub_ins.iter().enumerate() {
			pub_ins[i] = U256::from(x);
		}
		let proof_bytes = Bytes::from(proof_raw.proof.clone());

		let tx_call = et_wrapper_contract.verify(pub_ins, proof_bytes);
		let tx_res = tx_call.send();
		let tx = tx_res.await.map_err(|e| {
			eprintln!("{:?}", e);
			ClientError::TxError
		})?;
		let res = tx.await.map_err(|e| {
			eprintln!("{:?}", e);
			ClientError::TxError
		})?;

		if let Some(receipt) = res {
			println!("Transaction status: {:?}", receipt.status);
		}

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use crate::{
		manager::NUM_NEIGHBOURS,
		utils::{deploy_as, deploy_et_wrapper, deploy_verifier},
		Client, ClientConfig,
	};
	use eigen_trust_circuit::{
		utils::{read_bytes_data, read_json_data},
		ProofRaw,
	};
	use ethers::{abi::Address, utils::Anvil};

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

		let dummy_user = [
			"Alice".to_string(),
			"2L9bbXNEayuRMMbrWFynPtgkrXH1iBdfryRH9Soa8M67".to_string(),
			"9rBeBVtbN2MkHDTpeAouqkMWNFJC6Bxb6bXH9jUueWaF".to_string(),
		];
		let user_secrets_raw = vec![dummy_user; NUM_NEIGHBOURS];

		let config = ClientConfig {
			ops: [200, 200, 200, 200, 200],
			secret_key: [
				"2L9bbXNEayuRMMbrWFynPtgkrXH1iBdfryRH9Soa8M67".to_string(),
				"9rBeBVtbN2MkHDTpeAouqkMWNFJC6Bxb6bXH9jUueWaF".to_string(),
			],
			as_address: as_address_string,
			et_verifier_wrapper_address: et_verifier_address_string,
			mnemonic,
			ethereum_node_url: node_url,
		};

		let et_client = Client::new(config, user_secrets_raw);
		let res = et_client.attest().await;
		assert!(res.is_ok());

		drop(anvil);
	}

	#[tokio::test]
	async fn should_verify_proof() {
		let anvil = Anvil::new().spawn();
		let mnemonic = "test test test test test test test test test test test junk".to_string();
		let node_url = anvil.endpoint();
		let et_contract = read_bytes_data("et_verifier");
		let et_verifier_address = deploy_verifier(&mnemonic, &node_url, et_contract).await.unwrap();
		let et_verifier_wr =
			deploy_et_wrapper(&mnemonic, &node_url, et_verifier_address).await.unwrap();
		let et_verifier_address_string = format!("{:?}", et_verifier_wr);

		let dummy_user = [
			"Alice".to_string(),
			"2L9bbXNEayuRMMbrWFynPtgkrXH1iBdfryRH9Soa8M67".to_string(),
			"9rBeBVtbN2MkHDTpeAouqkMWNFJC6Bxb6bXH9jUueWaF".to_string(),
		];
		let user_secrets_raw = vec![dummy_user; NUM_NEIGHBOURS];

		let config = ClientConfig {
			ops: [200, 200, 200, 200, 200],
			secret_key: [
				"2L9bbXNEayuRMMbrWFynPtgkrXH1iBdfryRH9Soa8M67".to_string(),
				"9rBeBVtbN2MkHDTpeAouqkMWNFJC6Bxb6bXH9jUueWaF".to_string(),
			],
			as_address: format!("{:?}", Address::default()),
			et_verifier_wrapper_address: et_verifier_address_string,
			mnemonic,
			ethereum_node_url: node_url,
		};

		let et_client = Client::new(config, user_secrets_raw);
		let proof_raw: ProofRaw = read_json_data("et_proof").unwrap();
		let res = et_client.verify(proof_raw).await;
		assert!(res.is_ok());

		drop(anvil);
	}
}
