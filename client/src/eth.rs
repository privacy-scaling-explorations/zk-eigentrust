/// Ethereum Utility Module
///
/// This module provides types and functionalities for Ethereum blockchain interactions.
use crate::setup_client;
use eigen_trust_circuit::{
	dynamic_sets::native::ECDSAPublicKey,
	halo2::halo2curves::bn256::Fr as Scalar,
	utils::{read_yul_data, write_bytes_data},
	verifier::{compile_yul, encode_calldata},
	Proof as NativeProof,
};
use ethers::{
	abi::Address,
	middleware::SignerMiddleware,
	prelude::{abigen, k256::ecdsa::SigningKey, Abigen, ContractError},
	providers::{Http, Middleware, Provider},
	signers::{
		coins_bip39::{English, Mnemonic},
		LocalWallet,
	},
	solc::{artifacts::ContractBytecode, Solc},
	types::TransactionRequest,
	utils::keccak256,
};
use secp256k1::SecretKey;
use std::{
	env,
	fs::{self, write},
};

// Generate contract bindings
abigen!(AttestationStation, "../data/AttestationStation.json");

/// ContractError type alias
pub type CntrError = ContractError<SignerMiddleware<Provider<Http>, LocalWallet>>;

/// Deploy AttestationStation contract
pub async fn deploy_as(mnemonic_phrase: &str, node_url: &str) -> Result<Address, CntrError> {
	let client = setup_client(mnemonic_phrase, node_url);
	let contract = AttestationStation::deploy(client, ())?.send().await?;
	let addr = contract.address();

	Ok(addr)
}

/// Deploy EtVerifier contract
pub async fn deploy_verifier(
	mnemonic_phrase: &str, node_url: &str, contract_bytes: Vec<u8>,
) -> Result<Address, CntrError> {
	let client = setup_client(mnemonic_phrase, node_url);
	let tx = TransactionRequest::default().data(contract_bytes);
	let pen_tx = client.send_transaction(tx, None).await.unwrap();
	let tx = pen_tx.await;

	let res = tx.unwrap();
	let rec = res.unwrap();
	let addr = rec.contract_address.unwrap();

	Ok(addr)
}

/// Call the EtVerifier contract
pub async fn call_verifier(
	mnemonic_phrase: &str, node_url: &str, verifier_address: Address, proof: NativeProof,
) {
	let calldata = encode_calldata::<Scalar>(&[proof.pub_ins], &proof.proof);
	let client = setup_client(mnemonic_phrase, node_url);

	let tx = TransactionRequest::default().data(calldata).to(verifier_address);
	let pen_tx = client.send_transaction(tx, None).await.unwrap();

	let res = pen_tx.await.unwrap();
	println!("{:#?}", res);
}

/// Compile the solidity contracts
pub fn compile_sol_contract() {
	let curr_dir = env::current_dir().unwrap();
	let contracts_dir = curr_dir.join("../data/");

	// compile it
	let contracts = Solc::default().compile_source(&contracts_dir).unwrap();
	for (name, contr) in contracts.contracts_iter() {
		let bindings_path = contracts_dir.join(format!("{}.rs", name));
		let cntr_path = contracts_dir.join(format!("{}.json", name));
		println!("{:?}", name);
		let contract: ContractBytecode = contr.clone().into();
		let abi = contract.clone().abi.unwrap();
		let abi_json = serde_json::to_string(&abi).unwrap();
		let contract_json = serde_json::to_string(&contract).unwrap();
		let bindings = Abigen::new(name, abi_json.clone()).unwrap().generate().unwrap();

		// write to /data folder
		bindings.write_to_file(bindings_path.clone()).unwrap();
		write(cntr_path.clone(), contract_json).unwrap();
	}
}

/// Compile the yul contracts
pub fn compile_yul_contracts() {
	let curr_dir = env::current_dir().unwrap();
	let contracts_dir = curr_dir.join("../data/");
	let paths = fs::read_dir(contracts_dir).unwrap();

	for path in paths {
		let path = path.unwrap().path();
		let name_with_suffix = path.file_name().unwrap().to_str().unwrap();
		if !name_with_suffix.ends_with(".yul") {
			continue;
		}
		let name = name_with_suffix.strip_suffix(".yul").unwrap();
		// compile it
		let code = read_yul_data(name);
		let compiled_contract = compile_yul(&code);
		write_bytes_data(compiled_contract, name).unwrap();
	}
}

/// Returns a vector of ECDSA private keys derived from the given mnemonic phrase
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

		let secret_key =
			SecretKey::from_slice(&raw_pk.to_bytes()).expect("32 bytes, within curve order");

		keys.push(secret_key);
	}

	Ok(keys)
}

/// Construct an Ethereum address for the given ECDSA public key
pub fn address_from_public_key(pub_key: &ECDSAPublicKey) -> Result<Address, &'static str> {
	let pub_key_bytes: [u8; 65] = pub_key.serialize_uncompressed();

	// Hash with Keccak256
	let hashed_public_key = keccak256(&pub_key_bytes[1..]);

	// Get the last 20 bytes of the hash
	let address_bytes = &hashed_public_key[hashed_public_key.len() - 20..];

	Ok(Address::from_slice(address_bytes))
}

/// Construct a Scalar from the given Ethereum address
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
	use crate::eth::{address_from_public_key, call_verifier, deploy_as, deploy_verifier};
	use eigen_trust_circuit::{
		utils::{read_bytes_data, read_json_data},
		Proof, ProofRaw,
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
		let mnemonic = "test test test test test test test test test test test junk";
		let node_endpoint = anvil.endpoint();
		let res = deploy_as(mnemonic, &node_endpoint).await;
		assert!(res.is_ok());

		drop(anvil);
	}

	#[tokio::test]
	async fn test_deploy_verifier() {
		let anvil = Anvil::new().spawn();
		let mnemonic = "test test test test test test test test test test test junk";
		let node_endpoint = anvil.endpoint();
		let et_contract = read_bytes_data("et_verifier");
		let res = deploy_verifier(mnemonic, &node_endpoint, et_contract).await;
		assert!(res.is_ok());

		drop(anvil);
	}

	#[tokio::test]
	async fn test_call_verifier() {
		let anvil = Anvil::new().spawn();
		let mnemonic = "test test test test test test test test test test test junk";
		let node_endpoint = anvil.endpoint();

		let bytecode = read_bytes_data("et_verifier");
		let addr = deploy_verifier(mnemonic, &node_endpoint, bytecode).await.unwrap();

		let proof_raw: ProofRaw = read_json_data("et_proof").unwrap();
		let proof = Proof::from(proof_raw);
		call_verifier(mnemonic, &node_endpoint, addr, proof).await;

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
