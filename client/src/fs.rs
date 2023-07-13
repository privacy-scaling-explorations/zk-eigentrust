//! # Filesystem Actions Module.
//!
//! This module provides functionalities for filesystem actions.

use serde::de::DeserializeOwned;
use serde_json::from_reader;
use std::{
	env::current_dir,
	fs::{read_to_string, File},
	io::{BufReader, Result},
	path::PathBuf,
};

/// Enum representing the possible file extensions.
pub enum FileType {
	/// Binary file.
	Bin,
	/// CSV file.
	Csv,
	/// JSON file.
	Json,
	/// Rust file.
	Rs,
	/// Yul file.
	Yul,
}

impl FileType {
	/// Converts the enum variant into its corresponding file extension.
	fn as_str(&self) -> &'static str {
		match self {
			FileType::Bin => "bin",
			FileType::Csv => "csv",
			FileType::Json => "json",
			FileType::Rs => "rs",
			FileType::Yul => "yul",
		}
	}
}

/// Retrieves the path to the `assets` directory.
pub fn get_assets_path() -> Result<PathBuf> {
	let current_dir = current_dir()?;
	Ok(current_dir.join("assets"))
}

/// Helper function to get the path of a file in the `assets` directory.
pub fn get_file_path(file_name: &str, file_type: FileType) -> Result<PathBuf> {
	let assets_path = get_assets_path()?;
	Ok(assets_path.join(format!("{}.{}", file_name, file_type.as_str())))
}

/// Reads a JSON file from the `assets` directory and returns its deserialized contents.
pub fn read_json<T: DeserializeOwned>(file_name: &str) -> Result<T> {
	let json_path = get_file_path(file_name, FileType::Json)?;
	let file = File::open(json_path)?;
	let reader = BufReader::new(file);
	from_reader(reader).map_err(Into::into)
}

/// Reads a `.yul` file from the `assets` directory and returns its contents as a string.
pub fn read_yul(file_name: &str) -> Result<String> {
	let yul_path = get_file_path(file_name, FileType::Yul)?;
	read_to_string(yul_path)
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde::Deserialize;
	use std::fs::{self, File};
	use std::io::Write;

	#[derive(Deserialize, Debug, PartialEq)]
	struct TestStruct {
		field: String,
	}

	#[test]
	fn test_read_json() {
		let file_name = "test_read_json";

		// Write test file
		let mut file = File::create(get_file_path(file_name, FileType::Json).unwrap()).unwrap();
		file.write_all(b"{ \"field\": \"json data\" }").unwrap();

		// Test reading
		let data: TestStruct = read_json(file_name).unwrap();
		assert_eq!(data, TestStruct { field: "json data".to_string() });

		// Cleanup
		fs::remove_file(get_file_path(file_name, FileType::Json).unwrap()).unwrap();
	}

	#[test]
	fn test_read_yul() {
		let file_name = "test_read_yul";

		// Write test file
		let mut file = File::create(get_file_path(file_name, FileType::Yul).unwrap()).unwrap();
		file.write_all(b"yul data").unwrap();

		// Test reading
		let data = read_yul(file_name).unwrap();
		assert_eq!(data, "yul data");

		// Cleanup
		fs::remove_file(get_file_path(file_name, FileType::Yul).unwrap()).unwrap();
	}
}
