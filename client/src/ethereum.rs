use ethers::{
	prelude::abigen,
	providers::{Http, Provider},
};
use std::{convert::TryFrom, sync::Arc};

abigen!(AttestationStation, "data/AttestationStation.json");

/// Set up a client for interacting with ethereum node
pub fn setup_client(url: &str) -> Arc<Provider<Http>> {
	let provider = Provider::<Http>::try_from(url).unwrap();
	Arc::new(provider)
}
