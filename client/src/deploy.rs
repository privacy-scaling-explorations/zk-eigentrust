use ethers::{
	contract::ContractFactory,
	core::utils::Anvil,
	middleware::SignerMiddleware,
	prelude::ContractError,
	providers::{Http, Provider},
	signers::{LocalWallet, Signer},
	solc::{CompilerInput, Solc},
};
use std::{convert::TryFrom, path::Path, sync::Arc, time::Duration};

type CntrError = ContractError<SignerMiddleware<Provider<Http>, LocalWallet>>;

pub async fn deploy() -> Result<(), CntrError> {
	let anvil = Anvil::new().spawn();

	let input = CompilerInput::new("../contracts/AttestationStation.sol").unwrap();
	let compiled = Solc::default().compile(&input).expect("Could not compile contracts");
	// for (name, contract) in compiled.contracts_iter() {
	// 	println!("{:?}", name);
	// }
	// let (abi, bytecode, _) = compiled
	// 	.find("AttestationStation")
	// 	.expect("could not find contract")
	// 	.into_parts_or_default();

	// // 2. instantiate our wallet
	// let wallet: LocalWallet = anvil.keys()[0].clone().into();

	// // 3. connect to the network
	// let provider = Provider::<Http>::try_from(anvil.endpoint())
	// 	.unwrap()
	// 	.interval(Duration::from_millis(10u64));

	// // 4. instantiate the client with the wallet
	// let client = SignerMiddleware::new(provider,
	// wallet.with_chain_id(anvil.chain_id())); let client = Arc::new(client);

	// // 5. create a factory which will be used to deploy instances of the contract
	// let factory = ContractFactory::new(abi, bytecode, client.clone());

	// // 6. deploy it with the constructor arguments
	// let contract = factory.deploy("initial value".to_string())?.send().await?;

	// // 7. get the contract's address
	// let addr = contract.address();

	// println!("Deployed contract address: {:?}", addr);

	Ok(())
}
