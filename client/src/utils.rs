//! # Utils Module.
//!
//! This module contains generic utility functions.

use csv::{ReaderBuilder, Writer as CsvWriter};
use serde::de::DeserializeOwned;
use std::{env, fs::File, io::BufReader};

/// Creates new CSV file in the given path and stores the provided data.
pub fn create_csv_file<T, U, V>(filename: &str, content: T) -> Result<(), &'static str>
where
	T: IntoIterator<Item = U>,
	U: IntoIterator<Item = V>,
	V: AsRef<[u8]>,
{
	let path = format!("../data/{}.csv", filename);

	let mut writer = CsvWriter::from_path(path).map_err(|_| "Failed to open file")?;

	// Loop over content and write each item
	for record in content {
		writer.write_record(record).map_err(|_| "Failed to write record")?;
	}

	// Flush buffer
	writer.flush().map_err(|_| "Failed to flush buffer")?;

	Ok(())
}

/// Reads CSV data from a file into a vector of the given type.
pub fn read_csv_file<T: DeserializeOwned>(file_name: &str) -> Result<Vec<T>, &'static str> {
	let current_dir = env::current_dir().map_err(|_| "Failed to get current directory")?;

	let file_name = format!("{}.csv", file_name);
	let mut path = current_dir;
	path.push("../data");
	path.push(file_name);

	let file = File::open(&path).map_err(|_| "Failed to open file")?;

	let mut reader = ReaderBuilder::new().from_reader(BufReader::new(file));

	reader
		.deserialize()
		.map(|result| result.map_err(|_| "Failed to deserialize data"))
		.collect::<Result<Vec<T>, &'static str>>()
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde::Deserialize;
	use std::fs;

	#[test]
	fn test_create_and_read_csv() {
		// Define the test struct
		#[derive(Debug, Deserialize, PartialEq)]
		struct Record {
			peer_address: String,
			score: u32,
		}

		// Create the CSV file
		let filename = "test";
		let content = vec![
			vec!["peer_address", "score"],
			vec!["0x70997970c51812dc3a010c7d01b50e0d17dc7666", "1000"],
		];
		assert!(create_csv_file(filename, content).is_ok());

		// Read the CSV file
		let result = read_csv_file::<Record>(filename);

		// Assert
		assert!(result.is_ok());
		let records = result.unwrap();
		assert_eq!(records.len(), 1);
		assert_eq!(
			records[0],
			Record {
				peer_address: "0x70997970c51812dc3a010c7d01b50e0d17dc7666".into(),
				score: 1000
			}
		);

		// Clean up
		let file_path = format!("../data/{}.csv", filename);
		fs::remove_file(file_path).unwrap();
	}
}
