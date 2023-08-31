//! # Ethereum Module.
//!
//! This module provides types and functionalities for general ethereum interactions.

use crate::{
	att_station::AttestationStation, error::EigenError, ClientSigner, ECDSAKeypair, ECDSAPublicKey,
	Scalar,
};
use eigentrust_zk::halo2::halo2curves::{secp256k1::Secp256k1Affine, CurveAffine};
use ethers::{
	abi::Address,
	prelude::k256::ecdsa::SigningKey,
	signers::coins_bip39::{English, Mnemonic},
};
use std::sync::Arc;

/// Deploys the AttestationStation contract.
pub async fn deploy_as(signer: Arc<ClientSigner>) -> Result<Address, EigenError> {
	let res = AttestationStation::deploy(signer, ())
		.map_err(|e| EigenError::ContractError(e.to_string()))?;

	let transaction = res.send().await.map_err(|e| EigenError::TransactionError(e.to_string()))?;

	Ok(transaction.address())
}

/// Returns a vector of ECDSA private keys derived from the given mnemonic phrase.
pub fn ecdsa_keypairs_from_mnemonic(
	mnemonic: &str, count: u32,
) -> Result<Vec<ECDSAKeypair>, EigenError> {
	let mnemonic = Mnemonic::<English>::new_from_phrase(mnemonic)
		.map_err(|e| EigenError::ParsingError(e.to_string()))?;
	let mut keys = Vec::new();

	// The hardened derivation flag.
	const BIP32_HARDEN: u32 = 0x8000_0000;

	for i in 0..count {
		// Set standard derivation path 44'/60'/0'/0/i
		let derivation_path: Vec<u32> =
			vec![44 + BIP32_HARDEN, 60 + BIP32_HARDEN, BIP32_HARDEN, 0, i];

		let private_key = mnemonic
			.derive_key(&derivation_path, None)
			.map_err(|e| EigenError::KeysError(e.to_string()))?;
		let signing_key: &SigningKey = private_key.as_ref();

		let mut pk_bytes: [u8; 32] = [0; 32];
		pk_bytes.copy_from_slice(&signing_key.to_bytes()[0..32]);

		let scalar_pk_option = <Secp256k1Affine as CurveAffine>::ScalarExt::from_bytes(&pk_bytes);

		let scalar_pk = match scalar_pk_option.is_some().into() {
			true => scalar_pk_option.unwrap(),
			false => {
				return Err(EigenError::ParsingError(
					"Failed to construct scalar private key from bytes".to_string(),
				))
			},
		};

		keys.push(ECDSAKeypair::from_private_key(scalar_pk));
	}

	Ok(keys)
}

/// Constructs an Ethereum address for the given ECDSA public key.
pub fn address_from_ecdsa_key(pub_key: &ECDSAPublicKey) -> Address {
	let address: Vec<u8> = pub_key.to_address().to_bytes().to_vec();

	let mut address_array = [0; 20];
	address_array.copy_from_slice(&address[0..20]);

	Address::from(address_array)
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
		eth::{address_from_ecdsa_key, deploy_as},
		Client, ClientConfig, ECDSAKeypair,
	};
	use eigentrust_zk::halo2::halo2curves::secp256k1::Fq;
	use ethers::utils::{hex, Anvil};

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

	#[ignore]
	#[test]
	fn test_address_from_public_key() {
		// Test private key
		let private_key_str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
		// Expected address
		let address_str = "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

		let private_key_bytes: [u8; 32] = hex::decode(private_key_str)
			.expect("Decoding failed")
			.try_into()
			.expect("Wrong length");
		let expected_address_bytes: [u8; 20] =
			hex::decode(address_str).expect("Decoding failed").try_into().expect("Wrong length");

		let private_key_fq = Fq::from_bytes(&private_key_bytes).unwrap();
		let keypair = ECDSAKeypair::from_private_key(private_key_fq);

		let recovered_address = address_from_ecdsa_key(&keypair.public_key);

		assert_eq!(recovered_address.to_fixed_bytes(), expected_address_bytes);
	}
}
