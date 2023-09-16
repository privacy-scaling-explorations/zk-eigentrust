//! # Filesystem Actions Module.
//!
//! This module provides functionalities for filesystem actions.

use dotenv::{dotenv, var};
use eigentrust::{
	error::EigenError,
	storage::{BinFileStorage, JSONFileStorage, Storage},
	ClientConfig,
};
use log::warn;
use std::{env::current_dir, path::PathBuf};

/// Default mnemonic seed phrase.
const DEFAULT_MNEMONIC: &str = "test test test test test test test test test test test junk";
/// Library configuration file name.
pub const CONFIG_FILE: &str = "config";
/// EigenTrust generated proof file name.
pub const ET_PROOF_FILE: &str = "et-proof";
/// EigenTrust proving key file name.
pub const ET_PROVING_KEY_FILE: &str = "et-proving-key";
/// EigenTrust proof public inputs file name.
pub const ET_PUB_INP_FILE: &str = "et-public-inputs";
/// KZG parameters file name.
pub const PARAMS_FILE: &str = "kzg-params";

/// Enum representing the possible file extensions.
pub enum FileType {
	/// CSV file.
	Csv,
	/// JSON file.
	Json,
	/// Binary file.
	Bin,
}

impl FileType {
	/// Converts the enum variant into its corresponding file extension.
	fn as_str(&self) -> &'static str {
		match self {
			FileType::Csv => "csv",
			FileType::Json => "json",
			FileType::Bin => "bin",
		}
	}
}

// Enum for different EigenTrust binary files
pub enum EigenFile {
	KzgParams(u32),
	ProvingKey,
	EtProof,
	ETPublicInputs,
}

impl EigenFile {
	/// Loads the contents of the file.
	pub fn load(&self) -> Result<Vec<u8>, EigenError> {
		let filepath = self.path()?;
		BinFileStorage::new(filepath).load()
	}

	/// Saves the data to the file.
	pub fn save(&self, data: Vec<u8>) -> Result<(), EigenError> {
		let filepath = self.path()?;
		BinFileStorage::new(filepath).save(data)
	}

	/// Returns the path of the file.
	fn path(&self) -> Result<PathBuf, EigenError> {
		get_file_path(&self.filename(), FileType::Bin)
	}

	/// Returns the filename of the file.
	fn filename(&self) -> String {
		match self {
			EigenFile::KzgParams(pol_degree) => format!("{}-{}", PARAMS_FILE, pol_degree),
			EigenFile::ProvingKey => ET_PROVING_KEY_FILE.to_string(),
			EigenFile::EtProof => ET_PROOF_FILE.to_string(),
			EigenFile::ETPublicInputs => ET_PUB_INP_FILE.to_string(),
		}
	}
}

/// Loads the mnemonic from the environment file.
pub fn load_mnemonic() -> String {
	dotenv().ok();
	var("MNEMONIC").unwrap_or_else(|_| {
		warn!("MNEMONIC environment variable is not set. Using default.");
		DEFAULT_MNEMONIC.to_string()
	})
}

/// Retrieves the path to the `assets` directory.
pub fn get_assets_path() -> Result<PathBuf, EigenError> {
	current_dir().map_err(EigenError::IOError).map(|current_dir| {
		// Workaround for the tests running in the `client` directory.
		#[cfg(test)]
		{
			current_dir.join("assets")
		}

		#[cfg(not(test))]
		{
			current_dir.join("eigentrust-cli/assets")
		}
	})
}

/// Helper function to get the path of a file in the `assets` directory.
pub fn get_file_path(file_name: &str, file_type: FileType) -> Result<PathBuf, EigenError> {
	let assets_path = get_assets_path()?;
	Ok(assets_path.join(format!("{}.{}", file_name, file_type.as_str())))
}

/// Loads the configuration file.
pub fn load_config() -> Result<ClientConfig, EigenError> {
	let filepath = get_file_path(CONFIG_FILE, FileType::Json)?;
	JSONFileStorage::<ClientConfig>::new(filepath).load()
}
