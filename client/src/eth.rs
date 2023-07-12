//! # Ethereum Module.
//!
//! This module provides types and functionalities for general ethereum interactions.

use crate::{
	attestation::ECDSAPublicKey,
	error::EigenError,
	eth::bindings::AttestationStation,
	fs::{get_data_directory, get_file_path, read_yul, write_binary, FileType},
	ClientSigner,
};
use eigen_trust_circuit::{
	halo2::halo2curves::bn256::Fr as Scalar,
	verifier::{compile_yul, encode_calldata},
	Proof as NativeProof,
};
use ethers::{
	abi::Address,
	prelude::{k256::ecdsa::SigningKey, Abigen, ContractError},
	providers::Middleware,
	signers::coins_bip39::{English, Mnemonic},
	solc::{artifacts::ContractBytecode, Solc},
	types::TransactionRequest,
	utils::keccak256,
};
use secp256k1::SecretKey;
use std::{
	fs::{read_dir, write},
	sync::Arc,
};

/// The contract bindings module.
/// This is a workaround for the `abigen` macro not supporting doc comments as attributes.
pub mod bindings {
	#![allow(missing_docs)]
	ethers::prelude::abigen!(AttestationStation, "../data/AttestationStation.json");
}

/// Deploys the AttestationStation contract.
pub async fn deploy_as(signer: Arc<ClientSigner>) -> Result<Address, ContractError<ClientSigner>> {
	let contract = AttestationStation::deploy(signer, ())?.send().await?;
	Ok(contract.address())
}

/// Deploys the EtVerifier contract.
pub async fn deploy_verifier(
	signer: Arc<ClientSigner>, contract_bytes: Vec<u8>,
) -> Result<Address, ContractError<ClientSigner>> {
	let tx = TransactionRequest::default().data(contract_bytes);
	let pen_tx = signer.send_transaction(tx, None).await.unwrap();
	let tx = pen_tx.await;

	let rec = tx.unwrap().unwrap();
	Ok(rec.contract_address.unwrap())
}

/// Calls the EtVerifier contract.
pub async fn call_verifier(
	signer: Arc<ClientSigner>, verifier_address: Address, proof: NativeProof,
) {
	let calldata = encode_calldata::<Scalar>(&[proof.pub_ins], &proof.proof);

	let tx = TransactionRequest::default().data(calldata).to(verifier_address);
	let res = signer.send_transaction(tx, None).await.unwrap().await.unwrap();
	println!("{:#?}", res);
}

/// Compiles the AttestationStation contract.
pub fn compile_att_station() -> Result<(), EigenError> {
	let path =
		get_data_directory().map_err(|_| EigenError::ParseError)?.join("AttestationStation.sol");

	// compile it
	let contracts =
		Solc::default().compile_source(&path).map_err(|_| EigenError::ContractCompilationError)?;

	if contracts.errors.len() > 0 {
		return Err(EigenError::ContractCompilationError);
	}

	for (name, contr) in contracts.contracts_iter() {
		let contract: ContractBytecode = contr.clone().into();
		let abi = contract.clone().abi.ok_or(EigenError::ParseError)?;
		let abi_json = serde_json::to_string(&abi).map_err(|_| EigenError::ParseError)?;
		let contract_json = serde_json::to_string(&contract).map_err(|_| EigenError::ParseError)?;
		let bindings = Abigen::new(name, abi_json)
			.map_err(|_| EigenError::ParseError)?
			.generate()
			.map_err(|_| EigenError::ParseError)?;

		bindings
			.write_to_file(get_file_path(name, FileType::Rs).unwrap())
			.map_err(|_| EigenError::ParseError)?;
		write(get_file_path(name, FileType::Json).unwrap(), contract_json)
			.map_err(|_| EigenError::ParseError)?;
	}
	Ok(())
}

/// Compiles the Yul contracts in the `data` directory.
pub fn compile_yul_contracts() {
	let data_dir = get_data_directory().unwrap();
	let paths = read_dir(data_dir).unwrap();

	for path in paths {
		if let Some(name_with_suffix) = path.unwrap().path().file_name().and_then(|n| n.to_str()) {
			if name_with_suffix.ends_with(".yul") {
				let name = name_with_suffix.strip_suffix(".yul").unwrap();
				let compiled_contract = compile_yul(&read_yul(name).unwrap());

				write_binary(compiled_contract, name).unwrap();
			}
		}
	}
}

/// Returns a vector of ECDSA private keys derived from the given mnemonic phrase.
pub fn ecdsa_secret_from_mnemonic(
	mnemonic: &str, count: u32,
) -> Result<Vec<SecretKey>, &'static str> {
	let mnemonic = Mnemonic::<English>::new_from_phrase(mnemonic).unwrap();
	let mut keys = Vec::new();

	// The hardened derivation flag.
	const BIP32_HARDEN: u32 = 0x8000_0000;

	for i in 0..count {
		// Set standard derivation path 44'/60'/0'/0/i
		let derivation_path: Vec<u32> =
			vec![44 + BIP32_HARDEN, 60 + BIP32_HARDEN, BIP32_HARDEN, 0, i];

		let derived_pk =
			mnemonic.derive_key(&derivation_path, None).expect("Failed to derive signing key");

		let raw_pk: &SigningKey = derived_pk.as_ref();

		let secret_key = SecretKey::from_slice(&raw_pk.to_bytes().as_slice())
			.expect("32 bytes, within curve order");

		keys.push(secret_key);
	}

	Ok(keys)
}

/// Constructs an Ethereum address for the given ECDSA public key.
pub fn address_from_public_key(pub_key: &ECDSAPublicKey) -> Result<Address, &'static str> {
	let pub_key_bytes: [u8; 65] = pub_key.serialize_uncompressed();

	// Hash with Keccak256
	let hashed_public_key = keccak256(&pub_key_bytes[1..]);

	// Get the last 20 bytes of the hash
	let address_bytes = &hashed_public_key[hashed_public_key.len() - 20..];

	Ok(Address::from_slice(address_bytes))
}

/// Constructs a Scalar from the given Ethereum address.
pub fn scalar_from_address(address: &Address) -> Result<Scalar, &'static str> {
	let mut address_fixed = address.to_fixed_bytes();
	address_fixed.reverse();

	let mut address_bytes = [0u8; 32];
	address_bytes[..address_fixed.len()].copy_from_slice(&address_fixed);

	let about = match Scalar::from_bytes(&address_bytes).is_some().into() {
		true => Scalar::from_bytes(&address_bytes).unwrap(),
		false => return Err("Failed to convert about address to scalar"),
	};

	Ok(about)
}

#[cfg(test)]
mod tests {
	use crate::{
		eth::{address_from_public_key, call_verifier, deploy_as, deploy_verifier},
		fs::{read_binary, read_json},
		Client, ClientConfig,
	};
	use eigen_trust_circuit::{Proof, ProofRaw};
	use ethers::{
		prelude::k256::ecdsa::SigningKey,
		signers::{Signer, Wallet},
		utils::Anvil,
	};
	use secp256k1::{PublicKey, Secp256k1, SecretKey};

	#[tokio::test]
	async fn test_deploy_as() {
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

		// Deploy
		let res = deploy_as(client.signer).await;
		assert!(res.is_ok());

		drop(anvil);
	}

	#[tokio::test]
	async fn test_deploy_verifier() {
		let anvil = Anvil::new().spawn();
		let et_contract = read_binary("et_verifier").unwrap();
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

		// Deploy
		let res = deploy_verifier(client.get_signer(), et_contract).await;
		assert!(res.is_ok());

		drop(anvil);
	}

	#[tokio::test]
	async fn test_call_verifier() {
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

		// Read contract data and deploy verifier
		let bytecode = read_binary("et_verifier").unwrap();
		let addr = deploy_verifier(client.get_signer(), bytecode).await.unwrap();

		// Read proof data and call verifier
		let proof_raw: ProofRaw = read_json("et_proof").unwrap();
		let proof = Proof::from(proof_raw);
		call_verifier(client.get_signer(), addr, proof).await;

		drop(anvil);
	}

	#[test]
	fn test_address_from_public_key() {
		let secp = Secp256k1::new();

		let secret_key_as_bytes = [0x40; 32];

		let secret_key =
			SecretKey::from_slice(&secret_key_as_bytes).expect("32 bytes, within curve order");

		let pub_key = PublicKey::from_secret_key(&secp, &secret_key);

		let recovered_address = address_from_public_key(&pub_key).unwrap();

		let expected_address =
			Wallet::from(SigningKey::from_bytes(secret_key_as_bytes.as_ref()).unwrap()).address();

		assert_eq!(recovered_address, expected_address);
	}
}
