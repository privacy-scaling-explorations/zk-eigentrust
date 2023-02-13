use ethers::{
	abi::Address,
	middleware::SignerMiddleware,
	prelude::{abigen, Abigen, ContractError},
	providers::{Http, Provider},
	signers::{coins_bip39::English, LocalWallet, MnemonicBuilder, Signer},
	solc::Solc,
};
use std::{env, fs::write, sync::Arc};

abigen!(AttestationStation, "../contracts/AttestationStation.json");
pub type SignerMiddlewareArc = Arc<SignerMiddleware<Provider<Http>, LocalWallet>>;
pub type CntrError = ContractError<SignerMiddleware<Provider<Http>, LocalWallet>>;

pub fn setup_client(mnemonic_phrase: &str, node_url: &str) -> SignerMiddlewareArc {
	let provider = Provider::<Http>::try_from(node_url).unwrap();
	let wallet = MnemonicBuilder::<English>::default().phrase(mnemonic_phrase).build().unwrap();
	let client = SignerMiddleware::new(provider, wallet.with_chain_id(31337u64));

	Arc::new(client)
}

pub async fn deploy(mnemonic_phrase: &str, node_url: &str) -> Result<Address, CntrError> {
	let client = setup_client(mnemonic_phrase, node_url);
	let contract = AttestationStation::deploy(client, ())?.send().await?;
	let addr = contract.address();

	println!("Deployed contract address: {:?}", addr);

	Ok(addr)
}

pub fn compile() {
	let curr_dir = env::current_dir().unwrap();
	let contracts_dir = curr_dir.join("../contracts/");
	println!("{:?}", contracts_dir);

	// compile it
	let contracts = Solc::default().compile_source(&contracts_dir).unwrap();
	let att_path = contracts_dir.join("AttestationStation.sol");
	let att_path_str = att_path.to_str().unwrap();
	let contract_name = "AttestationStation";
	let contract = contracts.get(att_path_str, contract_name).unwrap();
	let abi = contract.abi.unwrap();
	let abi_json = serde_json::to_string(abi).unwrap();
	let contract_json = serde_json::to_string(&contract).unwrap();

	let bindings = Abigen::new(&contract_name, abi_json.clone()).unwrap().generate().unwrap();

	// print to stdout if no output arg is given
	let bindings_dest = contracts_dir.join("AttestationStation.rs");
	let cntr_dest = contracts_dir.join("AttestationStation.json");

	bindings.write_to_file(bindings_dest).unwrap();
	write(cntr_dest, contract_json).unwrap();
}

#[cfg(test)]
mod test {
	use crate::utils::deploy;
	use ethers::utils::Anvil;

	#[tokio::test]
	async fn should_deploy_the_as_contract() {
		let anvil = Anvil::new().spawn();
		let mnemonic = "test test test test test test test test test test test junk";
		let node_endpoint = anvil.endpoint();
		let res = deploy(mnemonic, &node_endpoint).await;
		assert!(res.is_ok());

		drop(anvil);
	}
}
