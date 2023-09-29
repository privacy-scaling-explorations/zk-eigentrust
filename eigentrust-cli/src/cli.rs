//! # CLI Module.
//!
//! This module contains all CLI related data handling and conversions.

use crate::{
	bandada::BandadaApi,
	fs::{get_file_path, load_mnemonic, EigenFile, FileType},
	ClientConfig,
};
use clap::{Args, Parser, Subcommand};
use eigentrust::{
	attestation::{AttestationRaw, SignedAttestationRaw},
	circuit::{Circuit, ET_PARAMS_K, TH_PARAMS_K},
	error::EigenError,
	eth::deploy_as,
	storage::{
		str_to_20_byte_array, str_to_32_byte_array, AttestationRecord, CSVFileStorage,
		JSONFileStorage, ScoreRecord, Storage,
	},
	Client,
};
use ethers::{abi::Address, providers::Http, types::H160};
use log::{debug, info};
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
	/// Submits an attestation. Requires 'AttestData'.
	Attest(AttestData),
	/// Retrieves and saves all attestations.
	Attestations,
	/// Creates Bandada group.
	Bandada(BandadaData),
	/// Deploys the contracts.
	Deploy,
	/// Generates EigenTrust circuit proof.
	ETProof,
	/// Generates EigenTrust circuit proving key
	ETProvingKey,
	/// Verifies the stored eigentrust circuit proof.
	ETVerify,
	/// Generates KZG parameters
	KZGParams(KZGParamsData),
	/// Calculates the global scores from the saved attestations.
	LocalScores,
	/// Retrieves and saves all attestations and calculates the global scores.
	Scores,
	/// Generates a Threshold circuit proof for the selected participant.
	ThProof(ThProofData),
	/// Generates Threshold circuit proving key
	ThProvingKey,
	/// Verifies the stored Threshold circuit proof.
	ThVerify,
	/// Displays the current configuration.
	Show,
	/// Updates the configuration. Requires 'UpdateData'.
	Update(UpdateData),
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

/// KZGParams subcommand input.
#[derive(Args, Debug)]
pub struct KZGParamsData {
	/// Polynomial degree.
	#[clap(long = "k")]
	k: Option<String>,
}

/// ThresholdProof subcommand input.
#[derive(Args, Debug)]
pub struct ThProofData {
	/// Peer.
	#[clap(long = "peer")]
	peer: Option<String>,
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
	pub fn to_attestation_raw(&self, config: &ClientConfig) -> Result<AttestationRaw, EigenError> {
		// Parse Address
		let about = self
			.address
			.as_ref()
			.ok_or_else(|| EigenError::ValidationError("Missing address".to_string()))
			.and_then(|address| str_to_20_byte_array(address))?;

		// Use the `ClientConfig` instance to get domain
		let domain = str_to_20_byte_array(&config.domain)?;

		// Parse score
		let value = self
			.score
			.as_ref()
			.ok_or_else(|| EigenError::ValidationError("Missing score".to_string()))
			.and_then(|score| {
				score.parse::<u8>().map_err(|e| EigenError::ParsingError(e.to_string()))
			})?;

		// Parse message
		let message =
			self.message.as_ref().map_or(Ok([0u8; 32]), |message| str_to_32_byte_array(message))?;

		Ok(AttestationRaw::new(about, domain, value, message))
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

/// Handles submitting an attestation
pub async fn handle_attest(
	config: ClientConfig, attest_data: AttestData,
) -> Result<(), EigenError> {
	let attestation = attest_data.to_attestation_raw(&config)?;
	debug!("Attesting:{:?}", attestation);

	let mnemonic = load_mnemonic();
	let client = Client::new(config, mnemonic);
	client.attest(attestation).await?;
	Ok(())
}

/// Handles `attestations` command.
pub async fn handle_attestations(config: ClientConfig) -> Result<(), EigenError> {
	let mnemonic = load_mnemonic();
	let client = Client::new(config, mnemonic);

	let attestations = client.get_attestations().await?;

	if attestations.is_empty() {
		return Err(EigenError::AttestationError(
			"No attestations found.".to_string(),
		));
	}

	let attestation_records: Vec<AttestationRecord> =
		attestations.into_iter().map(|attestation| attestation.into()).collect();

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
			// Load scores
			let scores = CSVFileStorage::<ScoreRecord>::new("scores.csv".into()).load()?;

			// Find the participant record
			let participant_record = scores
				.iter()
				.find(|record| record.peer_address().as_str() == address)
				.ok_or(EigenError::ValidationError(
					"Participant not found in score records.".to_string(),
				))?;

			// Parse participant values with error handling
			let participant_score = participant_record
				.score_fr()
				.parse()
				.map_err(|_| EigenError::ParsingError("Failed to parse score.".to_string()))?;

			let score_num = participant_record
				.numerator()
				.parse()
				.map_err(|_| EigenError::ParsingError("Failed to parse numerator.".to_string()))?;

			let score_den = participant_record.denominator().parse().map_err(|_| {
				EigenError::ParsingError("Failed to parse denominator.".to_string())
			})?;

			let threshold = config
				.band_th
				.parse()
				.map_err(|_| EigenError::ParsingError("Failed to parse threshold.".to_string()))?;

			// Verify threshold
			let pass_threshold =
				Client::verify_threshold(participant_score, score_num, score_den, threshold);

			if pass_threshold {
				bandada_api.add_member(&config.band_id, identity_commitment).await?;
			} else {
				return Err(EigenError::ValidationError(format!(
					"Participant score below threshold. Score {} < Threshold {}.",
					participant_score, threshold
				)));
			}
		},
		Action::Remove => {
			bandada_api.remove_member(&config.band_id, identity_commitment).await?;
		},
	}

	Ok(())
}

/// Handles the deployment of AS contract.
pub async fn handle_deploy(config: ClientConfig) -> Result<(), EigenError> {
	let mnemonic = load_mnemonic();
	let client = Client::new(config, mnemonic);
	let as_address = deploy_as(client.get_signer()).await?;
	info!("AttestationStation deployed at {:?}", as_address);

	Ok(())
}

/// Handles eigentrust circuit proving key generation.
pub fn handle_et_pk() -> Result<(), EigenError> {
	let et_kzg_params = EigenFile::KzgParams(ET_PARAMS_K).load()?;
	let proving_key = Client::generate_et_pk(et_kzg_params)?;

	EigenFile::ProvingKey(Circuit::EigenTrust).save(proving_key)
}

/// Handles the eigentrust proof generation command.
pub async fn handle_et_proof(config: ClientConfig) -> Result<(), EigenError> {
	let mnemonic = load_mnemonic();
	let client = Client::new(config, mnemonic);

	let att_fp = get_file_path("attestations", FileType::Csv)?;

	handle_attestations(client.get_config().clone()).await?;
	let att_storage = CSVFileStorage::<AttestationRecord>::new(att_fp);
	let attestations: Result<Vec<SignedAttestationRaw>, EigenError> =
		att_storage.load()?.into_iter().map(|record| record.try_into()).collect();

	let proving_key = EigenFile::ProvingKey(Circuit::EigenTrust).load()?;
	let kzg_params = EigenFile::KzgParams(ET_PARAMS_K).load()?;

	// Generate proof
	let report = client.generate_et_proof(attestations?, kzg_params, proving_key)?;

	EigenFile::Proof(Circuit::EigenTrust).save(report.proof)?;
	EigenFile::PublicInputs(Circuit::EigenTrust).save(report.pub_inputs.to_bytes())?;

	Ok(())
}

/// Handles the eigentrust proof verification command.
pub async fn handle_et_verify(config: ClientConfig) -> Result<(), EigenError> {
	let mnemonic = load_mnemonic();
	let client = Client::new(config, mnemonic);

	// Load data
	let kzg_params = EigenFile::KzgParams(ET_PARAMS_K).load()?;
	let public_inputs = EigenFile::PublicInputs(Circuit::EigenTrust).load()?;
	let proving_key = EigenFile::ProvingKey(Circuit::EigenTrust).load()?;
	let proof = EigenFile::Proof(Circuit::EigenTrust).load()?;

	// Verify proof
	client.verify(kzg_params, public_inputs, proving_key, proof)?;

	info!("EigenTrust proof has been verified.");
	Ok(())
}

/// Handles KZG parameters generation.
pub fn handle_params(data: KZGParamsData) -> Result<(), EigenError> {
	let k = data.k.ok_or(EigenError::ValidationError(
		"Missing parameter 'k': polynomial degree.".to_string(),
	))?;

	let pol_degree = k.parse::<u32>().map_err(|e| {
		EigenError::ParsingError(format!("Error parsing polynomial degree - {}", e))
	})?;

	let params = Client::generate_kzg_params(pol_degree)?;

	EigenFile::KzgParams(pol_degree).save(params)
}

/// Handles `scores` and `local_scores` commands.
pub async fn handle_scores(
	config: ClientConfig, origin: AttestationsOrigin,
) -> Result<(), EigenError> {
	let mnemonic = load_mnemonic();
	let client = Client::new(config, mnemonic);
	let att_fp = get_file_path("attestations", FileType::Csv)?;

	// Get or Fetch attestations
	let attestations: Vec<SignedAttestationRaw> = match origin {
		AttestationsOrigin::Local => {
			let att_storage = CSVFileStorage::<AttestationRecord>::new(att_fp);

			let records = att_storage.load()?;

			// Verify there are attestations
			if records.is_empty() {
				return Err(EigenError::AttestationError(
					"No attestations found.".to_string(),
				));
			}

			let attestations: Result<Vec<SignedAttestationRaw>, EigenError> =
				records.into_iter().map(|record| record.try_into()).collect();

			attestations?
		},
		AttestationsOrigin::Fetch => {
			handle_attestations(client.get_config().clone()).await?;

			let att_storage = CSVFileStorage::<AttestationRecord>::new(att_fp);
			let attestations: Result<Vec<SignedAttestationRaw>, EigenError> =
				att_storage.load()?.into_iter().map(|record| record.try_into()).collect();

			attestations?
		},
	};

	// Calculate scores
	let score_records: Vec<ScoreRecord> =
		client.calculate_scores(attestations)?.into_iter().map(ScoreRecord::from_score).collect();

	// Save scores
	let scores_fp = get_file_path("scores", FileType::Csv)?;
	let mut records_storage = CSVFileStorage::<ScoreRecord>::new(scores_fp);
	records_storage.save(score_records)?;

	info!(
		"Scores saved at \"{}\".",
		records_storage.filepath().display()
	);

	Ok(())
}

/// Handles threshold circuit proving key generation.
pub async fn handle_th_pk(config: ClientConfig) -> Result<(), EigenError> {
	let mnemonic = load_mnemonic();
	let client = Client::new(config, mnemonic);

	// Load KZG params
	let et_kzg_params = EigenFile::KzgParams(ET_PARAMS_K).load()?;
	let th_kzg_params = EigenFile::KzgParams(TH_PARAMS_K).load()?;

	// Get attestations
	let att_fp = get_file_path("attestations", FileType::Csv)?;
	handle_attestations(client.get_config().clone()).await?;
	let att_storage = CSVFileStorage::<AttestationRecord>::new(att_fp);
	let attestations: Result<Vec<SignedAttestationRaw>, EigenError> =
		att_storage.load()?.into_iter().map(|record| record.try_into()).collect();

	let proving_key = client.generate_th_pk(attestations?, et_kzg_params, th_kzg_params)?;

	EigenFile::ProvingKey(Circuit::Threshold).save(proving_key)
}

/// Handles threshold circuit proof generation.
pub async fn handle_th_proof(config: ClientConfig, data: ThProofData) -> Result<(), EigenError> {
	let mnemonic = load_mnemonic();
	let client = Client::new(config.clone(), mnemonic);

	// Load KZG params and proving key
	let et_kzg_params = EigenFile::KzgParams(ET_PARAMS_K).load()?;
	let th_kzg_params = EigenFile::KzgParams(TH_PARAMS_K).load()?;
	let proving_key = EigenFile::ProvingKey(Circuit::Threshold).load()?;

	// Get attestations
	let att_fp = get_file_path("attestations", FileType::Csv)?;
	handle_attestations(client.get_config().clone()).await?;
	let att_storage = CSVFileStorage::<AttestationRecord>::new(att_fp);
	let attestations: Result<Vec<SignedAttestationRaw>, EigenError> =
		att_storage.load()?.into_iter().map(|record| record.try_into()).collect();

	// Parse peer id
	let peer_id = match data.peer {
		Some(peer) => peer.parse::<u32>().map_err(|e| EigenError::ParsingError(e.to_string()))?,
		None => {
			return Err(EigenError::ValidationError(
				"Missing parameter 'peer': participant address.".to_string(),
			))
		},
	};

	let report = client.generate_th_proof(
		attestations?,
		et_kzg_params,
		th_kzg_params,
		proving_key,
		config.band_th.parse().unwrap(),
		peer_id,
	)?;

	EigenFile::Proof(Circuit::Threshold).save(report.proof)?;
	EigenFile::PublicInputs(Circuit::Threshold).save(report.pub_inputs.to_bytes())?;

	Ok(())
}

/// Handles the eigentrust proof verification command.
pub async fn handle_th_verify(config: ClientConfig) -> Result<(), EigenError> {
	let mnemonic = load_mnemonic();
	let client = Client::new(config, mnemonic);

	// Load data
	let kzg_params = EigenFile::KzgParams(TH_PARAMS_K).load()?;
	let public_inputs = EigenFile::PublicInputs(Circuit::Threshold).load()?;
	let proving_key = EigenFile::ProvingKey(Circuit::Threshold).load()?;
	let proof = EigenFile::Proof(Circuit::Threshold).load()?;

	// Verify proof
	client.verify(kzg_params, public_inputs, proving_key, proof)?;

	info!("Threshold proof has been verified.");
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

	let filepath = get_file_path("config", FileType::Json)?;
	let mut json_storage = JSONFileStorage::<ClientConfig>::new(filepath);

	json_storage.save(config.clone())
}

#[cfg(test)]
mod tests {
	use crate::cli::{AttestData, Cli};
	use clap::CommandFactory;
	use eigentrust::{
		attestation::AttestationRaw,
		storage::{str_to_20_byte_array, str_to_32_byte_array},
		ClientConfig,
	};

	#[test]
	fn test_cli() {
		Cli::command().debug_assert()
	}

	#[test]
	fn test_attest_data_to_attestation_raw() {
		let config = ClientConfig {
			as_address: "test".to_string(),
			band_id: "38922764296632428858395574229367".to_string(),
			band_th: "500".to_string(),
			band_url: "http://localhost:3000".to_string(),
			chain_id: "31337".to_string(),
			domain: "0x0000000000000000000000000000000000000000".to_string(),
			node_url: "http://localhost:8545".to_string(),
		};

		let address = "0x5fbdb2315678afecb367f032d93f642f64180aa3".to_string();
		let score = "5".to_string();
		let message =
			"473fe1d0de78c8f334d059013d902c13c8b53eb0f669caa9cad677ce1a601167".to_string();

		let data = AttestData {
			address: Some(address.clone()),
			score: Some(score),
			message: Some(message.clone()),
		};

		let attestation = data.to_attestation_raw(&config).unwrap();

		let expected_about = str_to_20_byte_array(&address).unwrap();
		let expected_domain = str_to_20_byte_array(&config.domain).unwrap();
		let expected_value = 5u8;
		let expected_message = str_to_32_byte_array(&message).unwrap();

		let expected_attestation = AttestationRaw::new(
			expected_about, expected_domain, expected_value, expected_message,
		);

		assert_eq!(attestation, expected_attestation);
	}
}
