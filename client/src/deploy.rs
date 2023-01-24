use ethers::{
	core::utils::Anvil,
	middleware::SignerMiddleware,
	prelude::{abigen, ContractError},
	providers::{Http, Provider},
	signers::{coins_bip39::English, LocalWallet, MnemonicBuilder, Signer, Wallet},
	types::Address,
};
use std::{convert::TryFrom, sync::Arc, time::Duration};

abigen!(
	AttestationStation,
	"client/contracts/AttestationStation.json"
);

type CntrError = ContractError<SignerMiddleware<Provider<Http>, LocalWallet>>;

pub async fn deploy() -> Result<Address, CntrError> {
	let client = setup_client();

	// 5. Deploy da contract
	let contract = AttestationStation::deploy(client, ())?.send().await?;

	// 6. get the contract's address
	let addr = contract.address();

	println!("Deployed contract address: {:?}", addr);

	Ok(addr)
}

pub fn setup_client() -> Arc<SignerMiddleware<Provider<Http>, LocalWallet>> {
	let provider = Provider::<Http>::try_from("http://localhost:8545").unwrap();
	let phrase = "test test test test test test test test test test test junk";
	let wallet = MnemonicBuilder::<English>::default().phrase(phrase).build().unwrap();

	// 4. instantiate the client with the wallet
	let client = SignerMiddleware::new(provider, wallet.with_chain_id(31337u64));

	Arc::new(client)
}
