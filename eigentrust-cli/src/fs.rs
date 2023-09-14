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
pub const CONFIG_FILENAME: &str = "config";
/// KZG parameters file name.
pub const PARAMS_FILENAME: &str = "kzg-params";
/// EigenTrust proving key file name.
pub const PROVING_KEY_FILENAME: &str = "et-proving-key";

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
	let filepath = get_file_path(CONFIG_FILENAME, FileType::Json)?;
	JSONFileStorage::<ClientConfig>::new(filepath).load()
}

/// Loads kzg parameters for constructing proving and veirifying keys
pub fn load_kzg_params(pol_degree: u32) -> Result<Vec<u8>, EigenError> {
	let filepath = get_file_path(
		&format!("{}-{}", PARAMS_FILENAME, pol_degree),
		FileType::Bin,
	)?;
	BinFileStorage::new(filepath).load()
}

/// Saves kzg parameters for constructing proving and veirifying keys
pub fn save_kzg_params(pol_degree: u32, params: Vec<u8>) -> Result<(), EigenError> {
	let filepath = get_file_path(
		&format!("{}-{}", PARAMS_FILENAME, pol_degree),
		FileType::Bin,
	)?;
	BinFileStorage::new(filepath).save(params)
}

/// Loads proving key from file
pub fn load_proving_key() -> Result<Vec<u8>, EigenError> {
	let filepath = get_file_path(PROVING_KEY_FILENAME, FileType::Bin)?;
	BinFileStorage::new(filepath).load()
}

/// Saves proving key to file
pub fn save_proving_key(proving_key: Vec<u8>) -> Result<(), EigenError> {
	let filepath = get_file_path(PROVING_KEY_FILENAME, FileType::Bin)?;
	BinFileStorage::new(filepath).save(proving_key)
}
