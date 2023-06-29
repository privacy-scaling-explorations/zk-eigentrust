//! # Storage Module.
//!
//! This module contains generic storage traits and implementations.

use crate::Score;
use csv::{ReaderBuilder, WriterBuilder};
use serde::Deserialize;
use serde::{de::DeserializeOwned, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::marker::PhantomData;
use std::path::PathBuf;

/// The main trait to be implemented by different storage types.
pub trait Storage<T> {
	/// Loads data from storage.
	fn load(&self) -> Result<T, &'static str>;
	/// Saves data to storage.
	fn save(&mut self, data: T) -> Result<(), &'static str>;
}

/// The `CSVFileStorage` struct provides a mechanism for persisting
/// and retrieving structured data to and from CSV files.
///
/// # Examples
///
/// ```no_run
/// use serde::{Serialize, Deserialize};
/// use std::path::PathBuf;
/// use eigen_trust_client::storage::{CSVFileStorage, Storage};
///
/// #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
/// struct Record {
///    id: u64,
///    name: String,
/// }
///
/// let filepath = PathBuf::from("/path/to/your/file.csv");
/// let mut storage = CSVFileStorage::<Record>::new(filepath);
///
/// let data = vec![Record { id: 1, name: "Alice".into() }];
///
/// // Save the data to the CSV file.
/// storage.save(data.clone()).unwrap();
///
/// // Load the data from the CSV file.
/// let loaded_data = storage.load().unwrap();
/// assert_eq!(data, loaded_data);
/// ```
pub struct CSVFileStorage<T> {
	filepath: PathBuf,
	phantom: PhantomData<T>,
}

impl<T> CSVFileStorage<T> {
	/// Creates a new CSVFileStorage.
	pub fn new(filepath: PathBuf) -> Self {
		Self { filepath, phantom: PhantomData }
	}
}

impl<T: Serialize + DeserializeOwned + Clone> Storage<Vec<T>> for CSVFileStorage<T> {
	fn load(&self) -> Result<Vec<T>, &'static str> {
		let file = File::open(&self.filepath).map_err(|_| "Failed to open file")?;
		let mut reader = ReaderBuilder::new().from_reader(BufReader::new(file));

		reader
			.deserialize()
			.map(|result| result.map_err(|_| "Failed to deserialize data"))
			.collect::<Result<Vec<T>, &'static str>>()
	}

	fn save(&mut self, data: Vec<T>) -> Result<(), &'static str> {
		let mut writer =
			WriterBuilder::new().from_path(&self.filepath).map_err(|_| "Failed to open file")?;

		// Loop over content and write each item
		for record in &data {
			writer.serialize(record).map_err(|_| "Failed to write record")?;
		}

		// Flush buffer
		writer.flush().map_err(|_| "Failed to flush buffer")?;

		Ok(())
	}
}

/// Score record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScoreRecord {
	/// The peer's address.
	peer_address: String,
	/// The peer's score.
	score_fr: String,
	/// Score numerator.
	numerator: String,
	/// Score denominator.
	denominator: String,
	/// Score.
	score: String,
}

impl ScoreRecord {
	/// Creates a new score record.
	pub fn new(
		peer_address: String, score_fr: String, numerator: String, denominator: String,
		score: String,
	) -> Self {
		Self { peer_address, score_fr, numerator, denominator, score }
	}

	/// Creates a new score record from a score.
	pub fn from_score(score: Score) -> Self {
		let (participant, score_fr, score_rat) = score;

		let peer_address = format!("{:?}", participant);

		let score_fr_hex = {
			let mut score_fr_bytes = score_fr.to_bytes();
			score_fr_bytes.reverse(); // Reverse bytes for big endian format
			score_fr_bytes.iter().map(|byte| format!("{:02x}", byte)).collect::<String>()
		};
		let score_fr_hex = format!("0x{}", score_fr_hex);

		let numerator = score_rat.numer().to_string();
		let denominator = score_rat.denom().to_string();
		let score = score_rat.to_integer().to_string();

		Self::new(peer_address, score_fr_hex, numerator, denominator, score)
	}

	/// Returns the peer's address.
	pub fn peer_address(&self) -> &String {
		&self.peer_address
	}

	/// Returns the peer's score.
	pub fn score_fr(&self) -> &String {
		&self.score_fr
	}

	/// Returns the score numerator.
	pub fn numerator(&self) -> &String {
		&self.numerator
	}

	/// Returns the score denominator.
	pub fn denominator(&self) -> &String {
		&self.denominator
	}

	/// Returns the score.
	pub fn score(&self) -> &String {
		&self.score
	}
}

#[cfg(test)]
mod tests {
	use crate::storage::*;
	use serde::{Deserialize, Serialize};
	use std::fs;
	use std::path::PathBuf;

	// Define the test struct
	#[derive(Debug, Deserialize, PartialEq, Clone, Serialize)]
	struct Record {
		peer_address: String,
		score: u32,
	}

	#[test]
	fn test_csv_file_storage() {
		// Create the CSV file
		let filename = "test.csv";
		let filepath = PathBuf::from("../data").join(filename);
		let mut csv_storage = CSVFileStorage::<Record>::new(filepath.clone());

		let content = vec![Record {
			peer_address: "0x70997970c51812dc3a010c7d01b50e0d17dc7666".to_string(),
			score: 1000,
		}];

		assert!(csv_storage.save(content.clone()).is_ok());

		// Read the CSV file
		let result = csv_storage.load();

		// Assert
		assert!(result.is_ok());
		let records: Vec<Record> = result.unwrap();
		assert_eq!(records.len(), 1);
		assert_eq!(records[0], content[0]);

		// Clean up
		fs::remove_file(filepath).unwrap();
	}
}
