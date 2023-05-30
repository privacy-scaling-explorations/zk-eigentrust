use crate::ClientConfig;
use clap::{Args, Parser, Subcommand};
use eigen_trust_circuit::utils::write_json_data;
use eigen_trust_client::attestation::{Attestation, DOMAIN_PREFIX, DOMAIN_PREFIX_LEN};
use ethers::{
	abi::Address,
	providers::Http,
	signers::coins_bip39::{English, Mnemonic},
	types::{H160, U256},
};
use std::str::FromStr;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
	#[command(subcommand)]
	pub mode: Mode,
}

/// Commands
#[derive(Subcommand)]
pub enum Mode {
	/// Submit an attestation. Requires 'AttestData'
	Attest(AttestData),
	/// Compile the contracts
	Compile,
	/// Deploy the contracts
	Deploy,
	/// Generate the proofs
	Proof,
	/// Display the current client configuration
	Show,
	/// Update the client configuration. Requires 'UpdateData'
	Update(UpdateData),
	/// Verify the proofs
	Verify,
}

/// Configuration update subcommand input
#[derive(Args, Debug)]
pub struct UpdateData {
	/// Address of the AttestationStation contract (20-byte ethereum address)
	#[clap(long = "as-address")]
	as_address: Option<String>,
	/// Domain id (20-byte hex string)
	#[clap(long = "domain")]
	domain: Option<String>,
	/// Ethereum wallet mnemonic phrase
	#[clap(long = "mnemonic")]
	mnemonic: Option<String>,
	/// URL of the Ethereum node to connect to
	#[clap(long = "node")]
	node_url: Option<String>,
	/// Address of the Verifier contract (20-byte ethereum address)
	#[clap(long = "verifier")]
	verifier_address: Option<String>,
}

/// Handle the CLI project configuration update
pub fn handle_update(config: &mut ClientConfig, data: UpdateData) -> Result<(), &'static str> {
	if let Some(as_address) = data.as_address {
		config.as_address =
			Address::from_str(&as_address).map_err(|_| "Failed to parse address.")?.to_string();
	}

	if let Some(domain) = data.domain {
		config.as_address =
			H160::from_str(&domain).map_err(|_| "Failed to parse domain")?.to_string();
	}

	if let Some(mnemonic) = data.mnemonic {
		Mnemonic::<English>::new_from_phrase(&mnemonic).map_err(|_| "Failed to parse mnemonic.")?;
		config.mnemonic = mnemonic;
	}

	if let Some(node_url) = data.node_url {
		Http::from_str(&node_url).map_err(|_| "Failed to parse node url.")?;
		config.node_url = node_url;
	}

	if let Some(verifier_address) = data.verifier_address {
		config.verifier_address = Address::from_str(&verifier_address)
			.map_err(|_| "Failed to parse address.")?
			.to_string();
	}

	write_json_data(config, "client-config").map_err(|_| "Failed to write config data.")
}

/// Attestation subcommand input
#[derive(Args, Debug)]
pub struct AttestData {
	/// Attested address (20-byte ethereum address)
	#[clap(long = "to")]
	address: Option<String>,
	/// Given score (0-255)
	#[clap(long = "score")]
	score: Option<String>,
	/// Attestation message (hex-encoded)
	#[clap(long = "message")]
	message: Option<String>,
	/// Attestation key
	#[clap(long = "key")]
	key: Option<String>,
}

impl AttestData {
	/// Converts `AttestData` to `Attestation`
	pub fn to_attestation(&self, config: &ClientConfig) -> Result<Attestation, &'static str> {
		// Parse Address
		let parsed_address: Address = self
			.address
			.as_ref()
			.ok_or("Missing address")?
			.parse()
			.map_err(|_| "Failed to parse address.")?;

		// Parse score
		let parsed_score: u8 = self
			.score
			.as_ref()
			.ok_or("Missing score")?
			.parse()
			.map_err(|_| "Failed to parse score. It must be a number between 0 and 255.")?;

		// Parse message
		let message = match &self.message {
			Some(message_str) => {
				let message = U256::from_str(message_str).map_err(|_| "Failed to parse message")?;
				Some(message)
			},
			None => None,
		};

		// Key
		let domain = H160::from_str(&config.domain).map_err(|_| "Failed to parse domain")?;
		let mut key_bytes: [u8; 32] = [0; 32];
		key_bytes[..DOMAIN_PREFIX_LEN].copy_from_slice(&DOMAIN_PREFIX);
		key_bytes[DOMAIN_PREFIX_LEN..].copy_from_slice(&domain.as_bytes());
		let key = U256::from(key_bytes);

		Ok(Attestation::new(parsed_address, key, parsed_score, message))
	}
}

#[cfg(test)]
mod tests {
	use crate::cli::{AttestData, Cli};
	use clap::CommandFactory;
	use eigen_trust_client::{attestation::DOMAIN_PREFIX, ClientConfig};
	use ethers::types::U256;
	use std::str::FromStr;

	#[test]
	fn test_cli() {
		Cli::command().debug_assert()
	}

	#[test]
	fn test_attest_data_to_attestation() {
		let config = ClientConfig {
			as_address: "test".to_string(),
			domain: "0x0000000000000000000000000000000000000000".to_string(),
			mnemonic: "test".to_string(),
			node_url: "http://localhost:8545".to_string(),
			verifier_address: "test".to_string(),
		};

		let data = AttestData {
			address: Some("0x5fbdb2315678afecb367f032d93f642f64180aa3".to_string()),
			score: Some("5".to_string()),
			message: Some("0x1234512345".to_string()),
			key: None,
		};

		let attestation = data.to_attestation(&config).unwrap();

		assert_eq!(
			attestation.about,
			"0x5fbdb2315678afecb367f032d93f642f64180aa3".parse().unwrap()
		);
		assert_eq!(attestation.value, 5);

		let mut expected_key_bytes: [u8; 32] = [0; 32];
		expected_key_bytes[..DOMAIN_PREFIX.len()].copy_from_slice(&DOMAIN_PREFIX);
		let expected_key = U256::from(expected_key_bytes);

		assert_eq!(attestation.key, expected_key);

		let expected_message = U256::from_str(&"0x1234512345".to_string()).unwrap();

		assert_eq!(attestation.message, expected_message);
	}
}
