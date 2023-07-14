//! # Ethereum Module.
//!
//! This module provides types and functionalities for general ethereum interactions.

use crate::{
	attestation::ECDSAPublicKey,
	error::EigenError,
	fs::{get_assets_path, get_file_path, FileType},
	ClientSigner,
};
use eigen_trust_circuit::halo2::halo2curves::bn256::Fr as Scalar;
use ethers::{
	abi::Address,
	prelude::{k256::ecdsa::SigningKey, Abigen, ContractFactory},
	signers::coins_bip39::{English, Mnemonic},
	solc::{Artifact, CompilerOutput, Solc},
	utils::keccak256,
};
use secp256k1::SecretKey;
use std::sync::Arc;

/// Compiles the AttestationStation contract.
pub fn compile_as() -> Result<CompilerOutput, EigenError> {
	let path =
		get_assets_path().map_err(|_| EigenError::ParseError)?.join("AttestationStation.sol");

	let compiler_output =
		Solc::default().compile_source(path).map_err(|_| EigenError::ContractCompilationError)?;

	if !compiler_output.errors.is_empty() {
		return Err(EigenError::ContractCompilationError);
	}

	Ok(compiler_output)
}

/// Generates the bindings for the AttestationStation contract and save them into a file.
pub fn gen_as_bindings() -> Result<(), EigenError> {
	let contracts = compile_as()?;

	for (name, contract) in contracts.contracts_iter() {
		let abi = contract.clone().abi.ok_or(EigenError::ParseError)?;
		let abi_json = serde_json::to_string(&abi).map_err(|_| EigenError::ParseError)?;

		let bindings = Abigen::new(name, abi_json)
			.map_err(|_| EigenError::ParseError)?
			.generate()
			.map_err(|_| EigenError::ParseError)?;

		bindings
			.write_to_file(get_file_path("attestation_station", FileType::Rs).unwrap())
			.map_err(|_| EigenError::ParseError)?;
	}

	Ok(())
}

/// Deploys the AttestationStation contract.
pub async fn deploy_as(signer: Arc<ClientSigner>) -> Result<Address, EigenError> {
	let contracts = compile_as()?;
	let mut address: Option<Address> = None;

	for (_, contract) in contracts.contracts_iter() {
		let (abi, bytecode, _) = contract.clone().into_parts();
		let abi = abi.ok_or(EigenError::ParseError)?;
		let bytecode = bytecode.ok_or(EigenError::ParseError)?;

		let factory = ContractFactory::new(abi, bytecode, signer.clone());

		match factory.deploy(()).unwrap().send().await {
			Ok(contract) => {
				address = Some(contract.address());
				break;
			},
			Err(_) => continue,
		}
	}

	address.ok_or(EigenError::ParseError)
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

		let secret_key = SecretKey::from_slice(raw_pk.to_bytes().as_slice())
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
		eth::{address_from_public_key, deploy_as},
		Client, ClientConfig,
	};
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
