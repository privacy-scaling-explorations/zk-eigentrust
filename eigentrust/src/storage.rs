//! # Storage Module.
//!
//! This module contains generic storage traits and implementations.

use crate::{
	attestation::{AttestationRaw, SignatureRaw, SignedAttestationRaw},
	error::EigenError,
	Score,
};
use csv::{ReaderBuilder, WriterBuilder};
use ethers::{
	types::{H160, H256, U256},
	utils::hex,
};
use serde::Deserialize;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{from_reader, to_string};
use std::io::{BufReader, Read, Write};
use std::marker::PhantomData;
use std::path::PathBuf;
use std::{fs::File, str::FromStr};

/// The main trait to be implemented by different storage types.
pub trait Storage<T> {
	/// The error type.
	type Err;

	/// Loads data from storage.
	fn load(&self) -> Result<T, Self::Err>;
	/// Saves data to storage.
	fn save(&mut self, data: T) -> Result<(), Self::Err>;
}

/// The `CSVFileStorage` struct provides a mechanism for persisting
/// and retrieving structured data to and from CSV files.
///
/// # Examples
///
/// ```no_run
/// use serde::{Serialize, Deserialize};
/// use std::path::PathBuf;
/// use eigentrust::storage::{CSVFileStorage, Storage};
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

	/// Returns the path to the file.
	pub fn filepath(&self) -> &PathBuf {
		&self.filepath
	}
}

impl<T: Serialize + DeserializeOwned + Clone> Storage<Vec<T>> for CSVFileStorage<T> {
	type Err = EigenError;

	fn load(&self) -> Result<Vec<T>, EigenError> {
		let file = File::open(&self.filepath).map_err(EigenError::IOError)?;
		let mut reader = ReaderBuilder::new().from_reader(BufReader::new(file));

		reader
			.deserialize()
			.map(|result| result.map_err(|e| EigenError::FileIOError(e.to_string())))
			.collect()
	}

	fn save(&mut self, data: Vec<T>) -> Result<(), EigenError> {
		let mut writer = WriterBuilder::new()
			.from_path(&self.filepath)
			.map_err(|e| EigenError::FileIOError(e.to_string()))?;

		// Loop over content and write each item
		for record in &data {
			writer.serialize(record).map_err(|e| EigenError::FileIOError(e.to_string()))?;
		}

		// Flush buffer
		writer.flush().map_err(|e| EigenError::FileIOError(e.to_string()))?;

		Ok(())
	}
}

/// The `JSONFileStorage` struct provides a mechanism for persisting
/// and retrieving structured data to and from JSON files.
pub struct JSONFileStorage<T> {
	filepath: PathBuf,
	phantom: PhantomData<T>,
}

impl<T> JSONFileStorage<T> {
	/// Creates a new JSONFileStorage.
	pub fn new(filepath: PathBuf) -> Self {
		Self { filepath, phantom: PhantomData }
	}

	/// Returns the path to the file.
	pub fn filepath(&self) -> &PathBuf {
		&self.filepath
	}
}

impl<T: Serialize + DeserializeOwned + Clone> Storage<T> for JSONFileStorage<T> {
	type Err = EigenError;

	fn load(&self) -> Result<T, Self::Err> {
		let file = File::open(&self.filepath).map_err(EigenError::IOError)?;
		let reader = BufReader::new(file);
		from_reader(reader).map_err(|e| EigenError::ParsingError(e.to_string()))
	}

	fn save(&mut self, data: T) -> Result<(), Self::Err> {
		let json_str = to_string(&data).map_err(|e| EigenError::ParsingError(e.to_string()))?;

		let mut file = File::create(&self.filepath).map_err(EigenError::IOError)?;
		file.write_all(json_str.as_bytes()).map_err(EigenError::IOError)
	}
}

/// The `BinFileStorage` struct provides a mechanism for persisting
/// and retrieving data to and from bin files.
pub struct BinFileStorage {
	filepath: PathBuf,
}

impl BinFileStorage {
	/// Creates a new BinFileStorage.
	pub fn new(filepath: PathBuf) -> Self {
		Self { filepath }
	}

	/// Returns the path to the file.
	pub fn filepath(&self) -> &PathBuf {
		&self.filepath
	}
}

impl Storage<Vec<u8>> for BinFileStorage {
	type Err = EigenError;

	fn load(&self) -> Result<Vec<u8>, Self::Err> {
		let mut file = File::open(&self.filepath).map_err(EigenError::IOError)?;
		let mut data = Vec::new();
		file.read_to_end(&mut data).map_err(EigenError::IOError)?;
		Ok(data)
	}

	fn save(&mut self, data: Vec<u8>) -> Result<(), Self::Err> {
		let mut file = File::create(&self.filepath).map_err(EigenError::IOError)?;
		file.write_all(&data).map_err(EigenError::IOError)
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
		let peer_address = format!("0x{}", hex::encode(score.address));
		let score_fr_hex = format!("0x{}", hex::encode(score.score_fr));
		let numerator = U256::from_big_endian(&score.score_rat.0).to_string();
		let denominator = U256::from_big_endian(&score.score_rat.1).to_string();
		let score_hex = U256::from_big_endian(&score.score_hex).to_string();

		Self::new(
			peer_address, score_fr_hex, numerator, denominator, score_hex,
		)
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

/// Attestation record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationRecord {
	/// Ethereum address of the peer being rated.
	about: String,
	/// Unique identifier for the domain in which peers are being rated.
	domain: String,
	/// Given rating for the action.
	value: String,
	/// Optional field for attaching additional information to the attestation.
	message: String,
	/// The 'r' value of the ECDSA signature.
	sig_r: String,
	/// The 's' value of the ECDSA signature.
	sig_s: String,
	/// Recovery id of the ECDSA signature.
	rec_id: String,
}

impl From<SignedAttestationRaw> for AttestationRecord {
	fn from(raw: SignedAttestationRaw) -> Self {
		let SignedAttestationRaw { attestation, signature } = raw;
		let AttestationRaw { about, domain, value, message } = attestation;
		let SignatureRaw { sig_r, sig_s, rec_id } = signature;

		Self {
			about: format!("0x{}", hex::encode(about)),
			domain: format!("0x{}", hex::encode(domain)),
			value: value.to_string(),
			message: format!("0x{}", hex::encode(message)),
			sig_r: format!("0x{}", hex::encode(sig_r)),
			sig_s: format!("0x{}", hex::encode(sig_s)),
			rec_id: rec_id.to_string(),
		}
	}
}

impl TryFrom<AttestationRecord> for SignedAttestationRaw {
	type Error = EigenError;

	fn try_from(record: AttestationRecord) -> Result<Self, Self::Error> {
		let AttestationRecord { about, domain, value, message, sig_r, sig_s, rec_id } = record;

		let attestation = AttestationRaw {
			about: str_to_20_byte_array(&about)?,
			domain: str_to_20_byte_array(&domain)?,
			value: value
				.parse::<u8>()
				.map_err(|_| EigenError::ConversionError("Failed to parse 'value'".to_string()))?,
			message: str_to_32_byte_array(&message)?,
		};

		let signature = SignatureRaw {
			sig_r: str_to_32_byte_array(&sig_r)?,
			sig_s: str_to_32_byte_array(&sig_s)?,
			rec_id: rec_id
				.parse::<u8>()
				.map_err(|_| EigenError::ConversionError("Failed to parse 'rec_id'".to_string()))?,
		};

		Ok(Self { attestation, signature })
	}
}

/// Converts a hex string to a 20 byte array.
pub fn str_to_20_byte_array(hex: &str) -> Result<[u8; 20], EigenError> {
	H160::from_str(hex)
		.map(|bytes| *bytes.as_fixed_bytes())
		.map_err(|e| EigenError::ConversionError(e.to_string()))
}

/// Converts a hex string to a 32 byte array.
pub fn str_to_32_byte_array(hex: &str) -> Result<[u8; 32], EigenError> {
	H256::from_str(hex)
		.map(|bytes| *bytes.as_fixed_bytes())
		.map_err(|e| EigenError::ConversionError(e.to_string()))
}

#[cfg(test)]
mod tests {
	use crate::storage::*;
	use serde::{Deserialize, Serialize};
	use std::{env::current_dir, fs};

	// Define the test struct
	#[derive(Debug, Deserialize, PartialEq, Clone, Serialize)]
	struct Record {
		peer_address: String,
		score: u32,
	}

	#[test]
	fn test_csv_file_storage() {
		// Create the CSV file
		let filepath = current_dir().unwrap().join("test.csv");
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

	#[test]
	fn test_json_file_storage() {
		// Create the JSON file
		let filepath = current_dir().unwrap().join("test.json");
		let mut json_storage = JSONFileStorage::<Record>::new(filepath.clone());

		let content = Record {
			peer_address: "0x70997970c51812dc3a010c7d01b50e0d17dc7666".to_string(),
			score: 1000,
		};

		// Save the content to the JSON file
		assert!(json_storage.save(content.clone()).is_ok());

		// Load the JSON file
		let result = json_storage.load();

		// Assert
		assert!(result.is_ok());
		let records: Record = result.unwrap();
		assert_eq!(records.peer_address, content.peer_address);
		assert_eq!(records.score, content.score);

		// Clean up
		fs::remove_file(filepath).unwrap();
	}
}
