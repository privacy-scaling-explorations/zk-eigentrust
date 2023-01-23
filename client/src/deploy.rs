use ethers::{
	core::utils::Anvil,
	middleware::SignerMiddleware,
	prelude::{abigen, ContractError},
	providers::{Http, Provider},
	signers::{LocalWallet, Signer},
};
use std::{convert::TryFrom, sync::Arc, time::Duration};

abigen!(
	AttestationStation,
	"client/contracts/AttestationStation.json"
);

type CntrError = ContractError<SignerMiddleware<Provider<Http>, LocalWallet>>;

pub async fn deploy() -> Result<String, CntrError> {
	let anvil = Anvil::new().spawn();

	// 2. instantiate our wallet
	let wallet: LocalWallet = anvil.keys()[0].clone().into();

	// 3. connect to the network
	let provider = Provider::<Http>::try_from(anvil.endpoint())
		.unwrap()
		.interval(Duration::from_millis(10u64));

	// 4. instantiate the client with the wallet
	let client = SignerMiddleware::new(provider, wallet.with_chain_id(anvil.chain_id()));
	let client = Arc::new(client);

	let contract = AttestationStation::deploy(client, ())?.send().await?;
	// 5. create a factory which will be used to deploy instances of the contract

	// 6. get the contract's address
	let addr = contract.address();

	println!("Deployed contract address: {:?}", addr);

	Ok(addr.to_string())
}
