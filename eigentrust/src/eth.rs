//! # Ethereum Module.
//!
//! This module provides types and functionalities for general ethereum interactions.

use crate::{
	att_station::AttestationStation, attestation::ECDSAPublicKey, error::EigenError, ClientSigner,
};
use eigentrust_zk::halo2::halo2curves::bn256::Fr as Scalar;
use ethers::{
	abi::Address,
	prelude::k256::ecdsa::SigningKey,
	signers::coins_bip39::{English, Mnemonic},
	utils::keccak256,
};
use secp256k1::SecretKey;
use std::sync::Arc;

/// Deploys the AttestationStation contract.
pub async fn deploy_as(signer: Arc<ClientSigner>) -> Result<Address, EigenError> {
	let res = AttestationStation::deploy(signer, ())
		.map_err(|e| EigenError::ContractError(e.to_string()))?;

	let transaction = res.send().await.map_err(|e| EigenError::TransactionError(e.to_string()))?;

	Ok(transaction.address())
}

/// Returns a vector of ECDSA private keys derived from the given mnemonic phrase.
pub fn ecdsa_secret_from_mnemonic(
	mnemonic: &str, count: u32,
) -> Result<Vec<SecretKey>, EigenError> {
	let mnemonic = Mnemonic::<English>::new_from_phrase(mnemonic)
		.map_err(|e| EigenError::ParsingError(e.to_string()))?;
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
pub fn address_from_public_key(pub_key: &ECDSAPublicKey) -> Address {
	let pub_key_bytes: [u8; 65] = pub_key.serialize_uncompressed();

	// Hash with Keccak256
	let hashed_public_key = keccak256(&pub_key_bytes[1..]);

	// Get the last 20 bytes of the hash
	let address_bytes = &hashed_public_key[hashed_public_key.len() - 20..];

	Address::from_slice(address_bytes)
}

/// Constructs a Scalar from the given Ethereum address.
pub fn scalar_from_address(address: &Address) -> Result<Scalar, EigenError> {
	let mut address_fixed = address.to_fixed_bytes();
	address_fixed.reverse();

	let mut address_bytes = [0u8; 32];
	address_bytes[..address_fixed.len()].copy_from_slice(&address_fixed);

	let about_opt = Scalar::from_bytes(&address_bytes);
	let about = match about_opt.is_some().into() {
		true => about_opt.unwrap(),
		false => {
			return Err(EigenError::ParsingError(
				"Failed to convert address to scalar".to_string(),
			))
		},
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

	const TEST_MNEMONIC: &'static str =
		"test test test test test test test test test test test junk";

	#[tokio::test]
	async fn test_deploy_as() {
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

		let recovered_address = address_from_public_key(&pub_key);

		let expected_address =
			Wallet::from(SigningKey::from_bytes(secret_key_as_bytes.as_ref().into()).unwrap())
				.address();

		assert_eq!(recovered_address, expected_address);
	}
}
