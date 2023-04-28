use crate::{attestation::Attestation, error::EigenError, ClientConfig};
use csv::Reader as CsvReader;
use eigen_trust_circuit::{
	eddsa::native::{PublicKey, SecretKey},
	halo2::halo2curves::bn256::Fr as Scalar,
	utils::{read_yul_data, write_bytes_data},
	verifier::{compile_yul, encode_calldata},
	Proof as NativeProof,
};
use ethers::{
	abi::{Address, RawLog},
	contract::EthEvent,
	middleware::SignerMiddleware,
	prelude::{
		abigen,
		k256::ecdsa::{self, SigningKey},
		Abigen, ContractError,
	},
	providers::{Http, Middleware, Provider},
	signers::{
		coins_bip39::{English, Mnemonic},
		LocalWallet, MnemonicBuilder, Signer, Wallet,
	},
	solc::{artifacts::ContractBytecode, Solc},
	types::{Filter, TransactionRequest, H256},
};
use serde::de::DeserializeOwned;
use std::{
	env,
	fs::{self, write, File},
	io::{BufReader, Error},
	path::Path,
	sync::Arc,
};

/// Reads the json file and deserialize it into the provided type
pub fn read_csv_file<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<Vec<T>, Error> {
	let path = path.as_ref();
	let file = File::open(path)?;
	let file = BufReader::new(file);
	let mut reader = CsvReader::from_reader(file);
	let mut records = Vec::new();
	for result in reader.deserialize() {
		let record: T = result?;
		records.push(record);
	}
	Ok(records)
}

/// Reads the json file and deserialize it into the provided type
pub fn read_csv_data<T: DeserializeOwned>(file_name: &str) -> Result<Vec<T>, Error> {
	let current_dir = env::current_dir().unwrap();
	let path = current_dir.join(format!("../data/{}.csv", file_name));
	let file = File::open(path)?;
	let file = BufReader::new(file);
	let mut reader = CsvReader::from_reader(file);
	let mut records = Vec::new();
	for result in reader.deserialize() {
		let record: T = result?;
		records.push(record);
	}
	Ok(records)
}

abigen!(AttestationStation, "../data/AttestationStation.json");
abigen!(EtVerifierWrapper, "../data/EtVerifierWrapper.json");
pub type SignerMiddlewareArc = Arc<SignerMiddleware<Provider<Http>, LocalWallet>>;
pub type CntrError = ContractError<SignerMiddleware<Provider<Http>, LocalWallet>>;

pub fn setup_client(mnemonic_phrase: &str, node_url: &str) -> SignerMiddlewareArc {
	let provider = Provider::<Http>::try_from(node_url).unwrap();
	let wallet = MnemonicBuilder::<English>::default().phrase(mnemonic_phrase).build().unwrap();
	let client = SignerMiddleware::new(provider, wallet.with_chain_id(31337u64));

	Arc::new(client)
}

pub async fn deploy_as(mnemonic_phrase: &str, node_url: &str) -> Result<Address, CntrError> {
	let client = setup_client(mnemonic_phrase, node_url);
	let contract = AttestationStation::deploy(client, ())?.send().await?;
	let addr = contract.address();

	println!("Deployed contract address: {:?}", addr);

	Ok(addr)
}

pub async fn deploy_et_wrapper(
	mnemonic_phrase: &str, node_url: &str, verifier_address: Address,
) -> Result<Address, CntrError> {
	let client = setup_client(mnemonic_phrase, node_url);
	let contract = EtVerifierWrapper::deploy(client, verifier_address)?.send().await?;
	let addr = contract.address();

	println!("Deployed contract address: {:?}", addr);

	Ok(addr)
}

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
	println!("Deployed contract address: {:?}", addr);
	Ok(addr)
}

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

pub fn compile_sol_contract() {
	let curr_dir = env::current_dir().unwrap();
	let contracts_dir = curr_dir.join("../data/");
	println!("{:?}", contracts_dir);

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

/// Construct the secret keys and public keys from the given raw data
pub fn keyset_from_raw<const N: usize>(
	sks_raw: [[&str; 2]; N],
) -> (Vec<SecretKey>, Vec<PublicKey>) {
	let mut sks = Vec::new();
	let mut pks = Vec::new();

	for sk_raw in sks_raw {
		let sk0_raw = bs58::decode(sk_raw[0]).into_vec().unwrap();
		let sk1_raw = bs58::decode(sk_raw[1]).into_vec().unwrap();

		let mut sk0_bytes: [u8; 32] = [0; 32];
		sk0_bytes.copy_from_slice(&sk0_raw);
		let mut sk1_bytes: [u8; 32] = [0; 32];
		sk1_bytes.copy_from_slice(&sk1_raw);

		let sk = SecretKey::from_raw([sk0_bytes, sk1_bytes]);
		let pk = sk.public();

		sks.push(sk);
		pks.push(pk);
	}

	(sks, pks)
}

/// Get the attestations from the contract
pub async fn get_attestations(config: &ClientConfig) -> Result<Vec<Attestation>, EigenError> {
	let client = setup_client(&config.mnemonic, &config.node_url);
	let filter = Filter::new()
		.address(config.as_address.parse::<Address>().unwrap())
		.event("AttestationCreated(address,address,bytes32,bytes)")
		.topic1(Vec::<H256>::new())
		.topic2(Vec::<H256>::new())
		.from_block(0);
	let logs = client.get_logs(&filter).await.unwrap();
	let mut attestations = Vec::new();

	println!("Indexed attestations: {}", logs.iter().len());

	for log in logs.iter() {
		let raw_log = RawLog::from((log.topics.clone(), log.data.to_vec()));
		let att_created = AttestationCreatedFilter::decode_log(&raw_log).unwrap();
		// let att_data = AttestationData::from_bytes(att_created.val.to_vec());
		// let att = Attestation::from(att_data);
		let att = Attestation { about: todo!(), key: todo!(), value: todo!(), message: todo!() };

		attestations.push(att);
	}

	Ok(attestations)
}

/// Returns a vector of Ethereum wallets derived from the given mnemonic phrase
pub fn eth_wallets_from_mnemonic(
	mnemonic: &str, count: u32,
) -> Result<Vec<Wallet<SigningKey>>, &'static str> {
	let wallet = MnemonicBuilder::<English>::default().phrase(mnemonic);
	let mut wallets = Vec::new();

	for i in 0..count {
		let child_key = wallet.clone().index(i).unwrap().build().unwrap();
		wallets.push(child_key);
	}

	Ok(wallets)
}

/// Returns a vector of EDDSA secret keys generated from the given mnemonic phrase
pub fn eddsa_sk_from_mnemonic(mnemonic: &str, count: u32) -> Result<Vec<SecretKey>, &'static str> {
	let mnemonic = Mnemonic::<English>::new_from_phrase(mnemonic).unwrap();
	let mut secret_keys = Vec::new();

	// The hardened derivation flag.
	const BIP32_HARDEN: u32 = 0x8000_0000;

	for i in 0..count {
		let derivation_path: Vec<u32> =
			vec![44 + BIP32_HARDEN, 60 + BIP32_HARDEN, BIP32_HARDEN, 0, i];

		let derived_pk =
			mnemonic.derive_key(&derivation_path, None).expect("Failed to derive signing key");

		let raw_pk: &ecdsa::SigningKey = derived_pk.as_ref();

		let hash_input = raw_pk.to_bytes();

		secret_keys.push(SecretKey::from_byte_array(&hash_input));
	}

	Ok(secret_keys)
}

#[cfg(test)]
mod test {
	use super::{call_verifier, deploy_as, deploy_verifier};
	use eigen_trust_circuit::{
		utils::{read_bytes_data, read_json_data},
		Proof, ProofRaw,
	};
	use ethers::utils::Anvil;

	#[tokio::test]
	async fn should_deploy_the_as_contract() {
		let anvil = Anvil::new().spawn();
		let mnemonic = "test test test test test test test test test test test junk";
		let node_endpoint = anvil.endpoint();
		let res = deploy_as(mnemonic, &node_endpoint).await;
		assert!(res.is_ok());

		drop(anvil);
	}

	#[tokio::test]
	async fn should_deploy_the_et_verifier_contract() {
		let anvil = Anvil::new().spawn();
		let mnemonic = "test test test test test test test test test test test junk";
		let node_endpoint = anvil.endpoint();
		let et_contract = read_bytes_data("et_verifier");
		let res = deploy_verifier(mnemonic, &node_endpoint, et_contract).await;
		assert!(res.is_ok());

		drop(anvil);
	}

	#[tokio::test]
	async fn should_call_et_verifier_contract() {
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
}
