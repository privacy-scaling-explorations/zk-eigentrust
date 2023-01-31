use ethers::{
	middleware::SignerMiddleware,
	prelude::{abigen, ContractError},
	providers::{Http, Provider},
	signers::{coins_bip39::English, LocalWallet, MnemonicBuilder, Signer},
	types::Address,
};
use std::{convert::TryFrom, sync::Arc};

abigen!(AttestationStation, "contracts/AttestationStation.json");

type CntrError = ContractError<SignerMiddleware<Provider<Http>, LocalWallet>>;

type SignerMiddlewareArc = Arc<SignerMiddleware<Provider<Http>, LocalWallet>>;

pub async fn deploy(client: SignerMiddlewareArc) -> Result<Address, CntrError> {
	// 5. Deploy da contract
	let contract = AttestationStation::deploy(client, ())?.send().await?;

	// 6. get the contract's address
	let addr = contract.address();

	println!("Deployed contract address: {:?}", addr);

	Ok(addr)
}

pub fn setup_client(mnemonic_phrase: &str, node_url: &str) -> SignerMiddlewareArc {
	let provider = Provider::<Http>::try_from(node_url).unwrap();
	let wallet = MnemonicBuilder::<English>::default().phrase(mnemonic_phrase).build().unwrap();

	// 4. instantiate the client with the wallet
	let client = SignerMiddleware::new(provider, wallet.with_chain_id(31337u64));

	Arc::new(client)
}
