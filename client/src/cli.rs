use crate::ClientConfig;
use clap::{Args, Parser, Subcommand};
use eigen_trust_circuit::utils::write_json_data;
use eigen_trust_client::attestation::Attestation;
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

/// Configuration update subcommand input
#[derive(Args, Debug)]
pub struct UpdateData {
	/// Address of the AttestationStation contract (20-byte ethereum address)
	#[clap(long = "att-address")]
	as_address: Option<String>,
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

	if let Some(mnemonic) = data.mnemonic {
		Mnemonic::<English>::new_from_phrase(&mnemonic).map_err(|_| "Failed to parse mnemonic.")?;
		config.mnemonic = mnemonic;
	}

	if let Some(node_url) = data.node_url {
		Http::from_str(&node_url).map_err(|_| "Failed to parse node url.")?;
		config.node_url = node_url;
	}

	if let Some(verifier_address) = data.verifier_address {
		config.et_verifier_wrapper_address = Address::from_str(&verifier_address)
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

			let message_bytes = hex::decode(message).map_err(|_| "Failed to parse message.")?;
			if message_bytes.len() > 32 {
				return Err("Message too long.");
			}

			// Calculate the starting index for the copy operation
			let start_index = 32 - message_bytes.len();
			message_array[start_index..].copy_from_slice(&message_bytes);
		}

		Ok(Attestation::new(
			parsed_address,
			[0; 32].into(),
			parsed_score,
			Some(message_array.into()),
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
