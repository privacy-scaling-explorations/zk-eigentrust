use crate::{attestation::Attestation, ClientConfig};
use clap::{Args, Parser, Subcommand};
use eigen_trust_circuit::utils::write_json_data;
use ethers::{
	abi::Address,
	providers::Http,
	signers::coins_bip39::{English, Mnemonic},
	utils::hex,
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

/// Configuration update input
#[derive(Args)]
pub struct UpdateData {
	field: Option<String>,
	new_data: Option<String>,
}

/// Configuration keys
pub enum ConfigKeys {
	AttestationStationAddress,
	Mnemonic,
	NodeUrl,
	VerifierAddress,
}

/// Implement `FromStr` for `ConfigKeys`
impl FromStr for ConfigKeys {
	type Err = &'static str;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"as_address" => Ok(ConfigKeys::AttestationStationAddress),
			"mnemonic" => Ok(ConfigKeys::Mnemonic),
			"node_url" => Ok(ConfigKeys::NodeUrl),
			"et_verifier_wrapper_address" => Ok(ConfigKeys::VerifierAddress),
			_ => Err("Invalid config field"),
		}
	}
}

/// Handle the CLI project configuration update
pub fn config_update(config: &mut ClientConfig, data: UpdateData) -> Result<(), &'static str> {
	let field = data.field.ok_or("Please provide a field to update.")?;
	let new_data =
		data.new_data.ok_or("Please provide the update data, e.g. update score \"Alice 100\"")?;

	match field.parse()? {
		ConfigKeys::AttestationStationAddress => {
			config.as_address =
				Address::from_str(&new_data).map_err(|_| "Failed to parse address.")?.to_string();
		},
		ConfigKeys::Mnemonic => {
			Mnemonic::<English>::new_from_phrase(&new_data)
				.map_err(|_| "Failed to parse mnemonic.")?;
			config.mnemonic = new_data;
		},
		ConfigKeys::NodeUrl => {
			Http::from_str(&new_data).map_err(|_| "Failed to parse node url.")?;
			config.node_url = new_data;
		},
		ConfigKeys::VerifierAddress => {
			config.et_verifier_wrapper_address =
				Address::from_str(&new_data).map_err(|_| "Failed to parse address.")?.to_string();
		},
	}

	write_json_data(config, "client-config").map_err(|_| "Failed to write config data.")
}

/// Attestation subcommand input
#[derive(Args, Debug)]
pub struct AttestData {
	/// The attested address - 20-byte ethereum address
	#[clap(long = "to")]
	address: Option<String>,
	/// The given score - Max 255
	#[clap(long = "score")]
	score: Option<String>,
	/// The attestation message - Hexadecimal value
	#[clap(long = "message")]
	message: Option<String>,
	/// The attestation key
	#[clap(long = "key")]
	key: Option<String>,
}

impl AttestData {
	/// Converts `AttestData` to `Attestation`
	pub fn to_attestation(&self) -> Result<Attestation, &'static str> {
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
		let mut message_array = [0u8; 32];
		if let Some(message) = &self.message {
			let message = message.trim_start_matches("0x");

			// If the message has an odd number of characters, prepend a '0'
			let message = if message.len() % 2 == 1 {
				format!("0{}", message)
			} else {
				message.to_string()
			};

			let message_bytes = hex::decode(&message).map_err(|_| "Failed to parse message.")?;
			if message_bytes.len() > 32 {
				return Err("Message too long.");
			}

			// Calculate the starting index for the copy operation
			let start_index = 32 - message_bytes.len();
			message_array[start_index..].copy_from_slice(&message_bytes);
		}

		Ok(Attestation::new(
			parsed_address,
			[0; 32],
			parsed_score,
			Some(message_array),
		))
	}
}

#[cfg(test)]
mod tests {
	use crate::cli::Cli;
	use clap::CommandFactory;

	#[test]
	fn test_cli() {
		Cli::command().debug_assert()
	}
}
