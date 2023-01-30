#![allow(missing_docs)]

use ethers::{
	middleware::SignerMiddleware,
	prelude::abigen,
	providers::{Http, Provider},
	signers::{coins_bip39::English, LocalWallet, MnemonicBuilder, Signer},
};
use std::{convert::TryFrom, sync::Arc};

abigen!(AttestationStation, "contracts/AttestationStation.json");

/// Set up a client for interacting with ethereum node
pub fn setup_client(url: &str) -> Arc<SignerMiddleware<Provider<Http>, LocalWallet>> {
	let provider = Provider::<Http>::try_from(url).unwrap();
	let phrase = "test test test test test test test test test test test junk";
	let wallet = MnemonicBuilder::<English>::default().phrase(phrase).build().unwrap();

	// 4. instantiate the client with the wallet
	let client = SignerMiddleware::new(provider, wallet.with_chain_id(31337u64));

	Arc::new(client)
}
