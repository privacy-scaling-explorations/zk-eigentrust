//! # CLI Module.
//!
//! This module contains all CLI related data handling and conversions.

use crate::{bandada::BandadaApi, ClientConfig};
use clap::{Args, Parser, Subcommand};
use eigen_trust_client::{
	att_station::AttestationCreatedFilter,
	attestation::AttestationEth,
	error::EigenError,
	fs::{get_file_path, FileType},
	storage::{AttestationRecord, CSVFileStorage, JSONFileStorage, ScoreRecord, Storage},
	Client,
};
use ethers::{
	abi::Address,
	providers::Http,
	types::{Uint8, H160, H256},
};
use log::info;
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
	/// Retrieves and saves all attestations.
	Attestations,
	/// Create Bandada group.
	Bandada(BandadaData),
	/// Compile the contracts.
	Compile,
	/// Deploy the contracts.
	Deploy,
	/// Calculate the global scores from the saved attestations.
	LocalScores,
	/// Generate the proofs.
	Proof,
	/// Retrieves and saves all attestations and calculates the global scores.
	Scores,
	/// Display the current client configuration.
	Show,
	/// Update the client configuration. Requires 'UpdateData'.
	Update(UpdateData),
	/// Verify the proofs.
	Verify,
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

/// Attestation subcommand input.
#[derive(Args, Debug)]
pub struct BandadaData {
	/// Desired action (add, remove).
	#[clap(long = "action")]
	action: Option<String>,
	/// Identity commitment.
	#[clap(long = "ic")]
	identity_commitment: Option<String>,
	/// Participant address.
	#[clap(long = "addr")]
	address: Option<String>,
}

/// Configuration update subcommand input.
#[derive(Args, Debug)]
pub struct UpdateData {
	/// AttestationStation contract address (20-byte ethereum address).
	#[clap(long = "as-address")]
	as_address: Option<String>,
	/// Bandada group id.
	#[clap(long = "band-id")]
	band_id: Option<String>,
	/// Bandada group threshold.
	#[clap(long = "band-th")]
	band_th: Option<String>,
	/// Bandada API base URL.
	#[clap(long = "band-url")]
	band_url: Option<String>,
	/// Network chain ID.
	#[clap(long = "chain-id")]
	chain_id: Option<String>,
	/// Attestation domain identifier (20-byte hex string).
	#[clap(long = "domain")]
	domain: Option<String>,
	/// Ethereum node URL.
	#[clap(long = "node")]
	node_url: Option<String>,
}

/// Bandada API action.
pub enum Action {
	Add,
	Remove,
}

/// Attestations Origin.
pub enum AttestationsOrigin {
	Local,
	Fetch,
}

impl AttestData {
	/// Converts `AttestData` to `Attestation`.
	pub fn to_attestation(&self, config: &ClientConfig) -> Result<AttestationEth, EigenError> {
		// Parse Address
		let parsed_address: Address = self
			.address
			.as_ref()
			.ok_or_else(|| EigenError::ParsingError("Missing address".to_string()))?
			.parse()
			.map_err(|_| EigenError::ParsingError("Failed to parse address.".to_string()))?;

		// Domain
		let domain = H160::from_str(&config.domain)
			.map_err(|_| EigenError::ParsingError("Failed to parse domain".to_string()))?;

		// Parse score
		let parsed_score: u8 = self
			.score
			.as_ref()
			.ok_or_else(|| EigenError::ParsingError("Missing score".to_string()))?
			.parse::<u8>()
			.map_err(|e| EigenError::ParsingError(e.to_string()))?;
		let score = Uint8::from(parsed_score);

		// Parse message
		let message = match &self.message {
			Some(message_str) => {
				let message = H256::from_str(message_str)
					.map_err(|e| EigenError::ParsingError(e.to_string()))?;
				Some(message)
			},
			None => None,
		};

		Ok(AttestationEth::new(parsed_address, domain, score, message))
	}
}

impl FromStr for Action {
	type Err = EigenError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"add" => Ok(Action::Add),
			"remove" => Ok(Action::Remove),
			_ => Err(EigenError::ParsingError("Invalid action.".to_string())),
		}
	}
}

/// Handle `attestations` command.
pub async fn handle_attestations(config: ClientConfig) -> Result<(), EigenError> {
	let client = Client::new(config);

	let attestations = client.get_attestations().await?;

	if attestations.is_empty() {
		return Err(EigenError::AttestationError(
			"No attestations found.".to_string(),
		));
	}

	let attestation_records = attestations
		.into_iter()
		.map(|log| AttestationRecord::from_log(&log))
		.collect::<Result<Vec<AttestationRecord>, EigenError>>()?;

	let filepath = get_file_path("attestations", FileType::Csv)?;

	let mut storage = CSVFileStorage::<AttestationRecord>::new(filepath);

	storage.save(attestation_records)?;

	info!(
		"Attestations saved at \"{}\".",
		storage.filepath().display()
	);

	Ok(())
}

/// Handles the bandada subcommand.
pub async fn handle_bandada(config: &ClientConfig, data: BandadaData) -> Result<(), EigenError> {
	let action: Action = data
		.action
		.as_deref()
		.ok_or(EigenError::ValidationError("Missing action.".to_string()))?
		.parse()?;
	let identity_commitment = data.identity_commitment.as_deref().ok_or(
		EigenError::ValidationError("Missing identity commitment.".to_string()),
	)?;
	let address = data
		.address
		.as_deref()
		.ok_or(EigenError::ValidationError("Missing address.".to_string()))?;

	let bandada_api = BandadaApi::new(&config.band_url)?;

	match action {
		Action::Add => {
			// Create a CSVFileStorage for scores
			let scores_storage = CSVFileStorage::<ScoreRecord>::new("scores.csv".into());

			// Read scores from the CSV file using load method from the Storage trait
			let scores = scores_storage.load()?;

			let participant_record = scores
				.iter()
				.find(|record| *record.peer_address().as_str() == *address)
				.ok_or(EigenError::ValidationError(
					"Participant not found in score records.".to_string(),
				))?;

			let participant_score: u32 = participant_record.score_fr().parse().map_err(|_| {
				EigenError::ParsingError("Failed to parse participant score.".to_string())
			})?;

			let threshold: u32 = config
				.band_th
				.parse()
				.map_err(|_| EigenError::ParsingError("Failed to parse threshold.".to_string()))?;

			if participant_score < threshold {
				return Err(EigenError::ValidationError(
					"Participant score is below the group threshold.".to_string(),
				));
			}

			bandada_api.add_member(&config.band_id, identity_commitment).await?;
		},
		Action::Remove => {
			bandada_api.remove_member(&config.band_id, identity_commitment).await?;
		},
	}

	Ok(())
}

/// Handle `scores` and `local_scores` commands.
pub async fn handle_scores(
	config: ClientConfig, origin: AttestationsOrigin,
) -> Result<(), EigenError> {
	let client = Client::new(config);

	let att_fp = get_file_path("attestations", FileType::Csv)?;

	// Get or Fetch attestations
	let attestations = match origin {
		AttestationsOrigin::Local => {
			let att_storage = CSVFileStorage::<AttestationRecord>::new(att_fp);

			let records = att_storage.load()?;

			// Verify there are attestations
			if records.is_empty() {
				return Err(EigenError::AttestationError(
					"No attestations found.".to_string(),
				));
			}

			let results: Result<Vec<_>, _> =
				records.into_iter().map(|record| record.to_log()).collect();
			let attestations: Vec<AttestationCreatedFilter> = results?;

			attestations
		},
		AttestationsOrigin::Fetch => {
			handle_attestations(client.get_config().clone()).await?;

			let att_storage = CSVFileStorage::<AttestationRecord>::new(att_fp);
			let results: Result<Vec<_>, _> =
				att_storage.load()?.into_iter().map(|record| record.to_log()).collect();
			let attestations: Vec<AttestationCreatedFilter> = results?;

			attestations
		},
	};

	// Calculate scores
	let score_records: Vec<ScoreRecord> = client
		.calculate_scores(attestations)
		.await?
		.into_iter()
		.map(ScoreRecord::from_score)
		.collect();

	let scores_fp = get_file_path("scores", FileType::Csv)?;

	// Save scores
	let mut records_storage = CSVFileStorage::<ScoreRecord>::new(scores_fp);

	records_storage.save(score_records)?;

	info!(
		"Scores saved at \"{}\".",
		records_storage.filepath().display()
	);

	Ok(())
}

/// Handles the CLI project configuration update.
pub fn handle_update(config: &mut ClientConfig, data: UpdateData) -> Result<(), EigenError> {
	if let Some(as_address) = data.as_address {
		config.as_address = Address::from_str(&as_address)
			.map_err(|e| EigenError::ParsingError(e.to_string()))?
			.to_string();
	}

	if let Some(band_id) = data.band_id {
		// TODO: Validate bandada group id type
		config.band_id = band_id
	}

	if let Some(band_th) = data.band_th {
		band_th.parse::<u32>().map_err(|e| EigenError::ParsingError(e.to_string()))?;
		config.band_th = band_th;
	}

	if let Some(band_url) = data.band_url {
		Http::from_str(&band_url).map_err(|e| EigenError::ParsingError(e.to_string()))?;
		config.band_url = band_url;
	}

	if let Some(chain_id) = data.chain_id {
		chain_id.parse::<u64>().map_err(|e| EigenError::ParsingError(e.to_string()))?;
		config.chain_id = chain_id;
	}

	if let Some(domain) = data.domain {
		config.as_address = H160::from_str(&domain)
			.map_err(|e| EigenError::ParsingError(e.to_string()))?
			.to_string();
	}

	if let Some(node_url) = data.node_url {
		Http::from_str(&node_url).map_err(|e| EigenError::ParsingError(e.to_string()))?;
		config.node_url = node_url;
	}

	let filepath = get_file_path("client_config", FileType::Json)?;
	let mut json_storage = JSONFileStorage::<ClientConfig>::new(filepath);

	json_storage.save(config.clone())
}

#[cfg(test)]
mod tests {
	use crate::cli::{AttestData, Cli};
	use clap::CommandFactory;
	use eigen_trust_client::{attestation::AttestationEth, ClientConfig};
	use ethers::types::{Uint8, H160, H256};
	use std::str::FromStr;

	#[test]
	fn test_cli() {
		Cli::command().debug_assert()
	}

	#[test]
	fn test_attest_data_to_attestation() {
		let config = ClientConfig {
			as_address: "test".to_string(),
			band_id: "38922764296632428858395574229367".to_string(),
			band_th: "500".to_string(),
			band_url: "http://localhost:3000".to_string(),
			chain_id: "31337".to_string(),
			domain: "0x0000000000000000000000000000000000000000".to_string(),
			node_url: "http://localhost:8545".to_string(),
		};

		let data = AttestData {
			address: Some("0x5fbdb2315678afecb367f032d93f642f64180aa3".to_string()),
			score: Some("5".to_string()),
			message: Some(
				"473fe1d0de78c8f334d059013d902c13c8b53eb0f669caa9cad677ce1a601167".to_string(),
			),
		};

		let attestation = data.to_attestation(&config).unwrap();

		let expected_about = "0x5fbdb2315678afecb367f032d93f642f64180aa3".parse().unwrap();
		let expected_domain = H160::from([0; 20]);
		let expected_value = Uint8::from(5);
		let expected_message = H256::from_str(
			&"473fe1d0de78c8f334d059013d902c13c8b53eb0f669caa9cad677ce1a601167".to_string(),
		)
		.unwrap();
		let expected_attestation = AttestationEth::new(
			expected_about,
			expected_domain,
			expected_value,
			Some(expected_message),
		);
		assert_eq!(attestation, expected_attestation);
	}
}
