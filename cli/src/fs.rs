//! # Filesystem Actions Module.
//!
//! This module provides functionalities for filesystem actions.

use dotenv::{dotenv, var};
use eigen_trust_client::{
	error::EigenError,
	storage::{JSONFileStorage, Storage},
	ClientConfig,
};
use log::warn;
use std::{env::current_dir, path::PathBuf};

#[allow(dead_code)]
/// Enum representing the possible file extensions.
pub enum FileType {
	/// CSV file.
	Csv,
	/// JSON file.
	Json,
	/// Rust file.
	Rs,
}

impl FileType {
	/// Converts the enum variant into its corresponding file extension.
	fn as_str(&self) -> &'static str {
		match self {
			FileType::Csv => "csv",
			FileType::Json => "json",
			FileType::Rs => "rs",
		}
	}
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
			current_dir.join("client/assets")
		}
	})
}

/// Helper function to get the path of a file in the `assets` directory.
pub fn get_file_path(file_name: &str, file_type: FileType) -> Result<PathBuf, EigenError> {
	let assets_path = get_assets_path()?;
	Ok(assets_path.join(format!("{}.{}", file_name, file_type.as_str())))
}

/// Loads the client configuration from a JSON file.
pub fn load_config() -> Result<ClientConfig, EigenError> {
	let filepath = get_file_path("client_config", FileType::Json)?;
	let json_storage = JSONFileStorage::<ClientConfig>::new(filepath);

	json_storage.load()
}

pub fn load_mnemonic() -> String {
	dotenv().ok();
	var("MNEMONIC").unwrap_or_else(|_| {
		warn!("MNEMONIC environment variable is not set. Using default.");
		"test test test test test test test test test test test junk".to_string()
	})
}
