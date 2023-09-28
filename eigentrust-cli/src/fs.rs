//! # Filesystem Actions Module.
//!
//! This module provides functionalities for filesystem actions.

use dotenv::{dotenv, var};
use eigentrust::{
	circuit::Circuit,
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
/// Proof file name.
pub const PROOF_FILE: &str = "proof";
/// Proving key file name.
pub const PROVING_KEY_FILE: &str = "proving-key";
/// Public inputs file name.
pub const PUB_INP_FILE: &str = "public-inputs";
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
	ProvingKey(Circuit),
	Proof(Circuit),
	PublicInputs(Circuit),
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
			EigenFile::ProvingKey(circuit) => format!("{}-{}", circuit.as_str(), PROVING_KEY_FILE),
			EigenFile::Proof(circuit) => format!("{}-{}", circuit.as_str(), PROOF_FILE),
			EigenFile::PublicInputs(circuit) => format!("{}-{}", circuit.as_str(), PUB_INP_FILE),
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

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;

	#[test]
	fn test_eigenfile_save_and_load() {
		let test_data = vec![1u8, 2, 3, 4, 5];
		let eigen_file = EigenFile::KzgParams(999);

		eigen_file.save(test_data.clone()).unwrap();
		let loaded_data = eigen_file.load().unwrap();
		assert_eq!(test_data, loaded_data);

		fs::remove_file(eigen_file.path().unwrap()).unwrap();
	}

	#[test]
	fn test_eigenfile_path_and_filename() {
		let eigen_file = EigenFile::KzgParams(999);
		let filename = eigen_file.filename();
		let path = eigen_file.path().unwrap();

		assert!(path.to_string_lossy().contains(&filename));
	}
}
