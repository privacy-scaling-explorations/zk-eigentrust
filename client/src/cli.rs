//! # CLI Module.
//!
//! This module contains all CLI related data handling and conversions.

use crate::{bandada::BandadaApi, ClientConfig};
use clap::{Args, Parser, Subcommand};
use eigen_trust_circuit::utils::write_json_data;
use eigen_trust_client::{
	attestation::{Attestation, DOMAIN_PREFIX, DOMAIN_PREFIX_LEN},
	utils::read_csv_file,
};
use ethers::{
	abi::Address,
	providers::Http,
	types::{H160, H256},
};
use serde::Deserialize;
use std::str::FromStr;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
	#[command(subcommand)]
	pub mode: Mode,
}

/// CLI commands.
#[derive(Subcommand)]
pub enum Mode {
	/// Submit an attestation. Requires 'AttestData'.
	Attest(AttestData),
	/// Create Bandada group.
	Bandada(BandadaData),
	/// Compile the contracts.
	Compile,
	/// Deploy the contracts.
	Deploy,
	/// Generate the proofs.
	Proof,
	/// Calculate the global scores.
	Scores,
	/// Display the current client configuration.
	Show,
	/// Update the client configuration. Requires 'UpdateData'.
	Update(UpdateData),
	/// Verify the proofs.
	Verify,
}

/// Configuration update subcommand input.
#[derive(Args, Debug)]
pub struct UpdateData {
	/// AttestationStation contract address (20-byte ethereum address).
	#[clap(long = "as-address")]
	as_address: Option<String>,
	/// Attestation domain identifier (20-byte hex string).
	#[clap(long = "domain")]
	domain: Option<String>,
	/// Ethereum node URL.
	#[clap(long = "node")]
	node_url: Option<String>,
	/// EigenTrustVerifier contract address (20-byte ethereum address).
	#[clap(long = "verifier")]
	verifier_address: Option<String>,
}

/// Handles the CLI project configuration update.
pub fn handle_update(config: &mut ClientConfig, data: UpdateData) -> Result<(), &'static str> {
	if let Some(as_address) = data.as_address {
		config.as_address =
			Address::from_str(&as_address).map_err(|_| "Failed to parse address.")?.to_string();
	}

	if let Some(domain) = data.domain {
		config.as_address =
			H160::from_str(&domain).map_err(|_| "Failed to parse domain")?.to_string();
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

/// Attestation subcommand input.
#[derive(Args, Debug)]
pub struct AttestData {
	/// Attested address (20-byte ethereum address).
	#[clap(long = "to")]
	address: Option<String>,
	/// Given score (0-255).
	#[clap(long = "score")]
	score: Option<String>,
	/// Attestation message (32-byte hex string).
	#[clap(long = "message")]
	message: Option<String>,
}

impl AttestData {
	/// Converts `AttestData` to `Attestation`.
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
				let message = H256::from_str(message_str).map_err(|_| "Failed to parse message")?;
				Some(message)
			},
			None => None,
		};

		// Key
		let domain = H160::from_str(&config.domain).map_err(|_| "Failed to parse domain")?;
		let mut key_bytes: [u8; 32] = [0; 32];
		key_bytes[..DOMAIN_PREFIX_LEN].copy_from_slice(&DOMAIN_PREFIX);
		key_bytes[DOMAIN_PREFIX_LEN..].copy_from_slice(domain.as_bytes());
		let key = H256::from(key_bytes);

		Ok(Attestation::new(parsed_address, key, parsed_score, message))
	}
}

/// Attestation subcommand input.
#[derive(Args, Debug)]
pub struct BandadaData {
	/// Desired action (add, remove).
	#[clap(long = "action")]
	action: Option<String>,
	/// Group id.
	#[clap(long = "id")]
	group_id: Option<String>,
}

#[allow(dead_code)]
/// Score record.
#[derive(Debug, Deserialize)]
pub struct ScoreRecord {
	/// The peer's address.
	peer_address: String,
	/// The peer's score.
	score_fr: String,
	/// Score numerator.
	numerator: String,
	/// Score denominator.
	denominator: String,
	/// Score.
	score: String,
}

/// Handles the bandada subcommand.
pub async fn handle_bandada(data: BandadaData) -> Result<(), &'static str> {
	// Ensure both action and id are provided
	let (action, group_id) = match (&data.action, &data.group_id) {
		(Some(action), Some(group_id)) => (action, group_id),
		_ => return Err("Missing action or id."),
	};

	// Initialize Bandada API client.
	let bandada_api = BandadaApi::new()?;

	// Load scores from file.
	let scores: Vec<ScoreRecord> = match read_csv_file("scores") {
		Ok(scores) => scores,
		Err(_) => return Err("Failed to read scores from file."),
	};

	// Handle action
	match action.as_str() {
		"add" => {
			// Iterate through scores and add each member
			for score in &scores {
				if bandada_api.add_member(group_id, &score.peer_address[0..11]).await.is_err() {
					return Err("Failed to add member.");
				}
			}
		},
		"remove" => {
			// Iterate through scores and remove each member
			for score in &scores {
				if bandada_api.remove_member(group_id, &score.peer_address[0..11]).await.is_err() {
					return Err("Failed to remove member.");
				}
			}
		},
		_ => return Err("Invalid action."),
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use crate::cli::{AttestData, Cli};
	use clap::CommandFactory;
	use eigen_trust_client::{attestation::DOMAIN_PREFIX, ClientConfig};
	use ethers::types::H256;
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
			node_url: "http://localhost:8545".to_string(),
			verifier_address: "test".to_string(),
		};

		let data = AttestData {
			address: Some("0x5fbdb2315678afecb367f032d93f642f64180aa3".to_string()),
			score: Some("5".to_string()),
			message: Some(
				"473fe1d0de78c8f334d059013d902c13c8b53eb0f669caa9cad677ce1a601167".to_string(),
			),
		};

		let attestation = data.to_attestation(&config).unwrap();

		assert_eq!(
			attestation.about,
			"0x5fbdb2315678afecb367f032d93f642f64180aa3".parse().unwrap()
		);
		assert_eq!(attestation.value, 5);

		let mut expected_key_bytes: [u8; 32] = [0; 32];
		expected_key_bytes[..DOMAIN_PREFIX.len()].copy_from_slice(&DOMAIN_PREFIX);
		let expected_key = H256::from(expected_key_bytes);

		assert_eq!(attestation.key, expected_key);

		let expected_message = H256::from_str(
			&"473fe1d0de78c8f334d059013d902c13c8b53eb0f669caa9cad677ce1a601167".to_string(),
		)
		.unwrap();

		assert_eq!(attestation.message, expected_message);
	}
}
