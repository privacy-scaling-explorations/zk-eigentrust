//! # Storage Module.
//!
//! This module contains generic storage traits and implementations.

use crate::att_station::AttestationCreatedFilter;
use crate::attestation::{
	address_from_signed_att, Attestation, AttestationPayload, SignedAttestation,
};
use crate::Score;
use csv::{ReaderBuilder, WriterBuilder};
use ethers::types::{Address, Bytes, H256};
use ethers::utils::hex;
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

	/// Returns the path to the file.
	pub fn filepath(&self) -> &PathBuf {
		&self.filepath
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

/// Attestation record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationRecord {
	/// Ethereum address of the peer being rated.
	about: String,
	/// Unique identifier for the action being rated.
	key: String,
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

impl AttestationRecord {
	/// Creates a new AttestationRecord from an Attestation log.
	pub fn from_log(log: &AttestationCreatedFilter) -> Self {
		let payload = AttestationPayload::from_log(log).unwrap();
		let attestation = Attestation::from_log(log).unwrap();
		let (sig_r, sig_s, rec_id) = payload.get_raw_signature();

		Self {
			about: Self::encode_bytes_to_hex(attestation.about.as_fixed_bytes()),
			key: Self::encode_bytes_to_hex(attestation.key.as_fixed_bytes()),
			value: attestation.value.to_string(),
			message: Self::encode_bytes_to_hex(attestation.message.as_fixed_bytes()),
			sig_r: Self::encode_bytes_to_hex(&sig_r),
			sig_s: Self::encode_bytes_to_hex(&sig_s),
			rec_id: rec_id.to_string(),
		}
	}

	/// Returns a log from an AttestationRecord.
	pub fn to_log(&self) -> Result<AttestationCreatedFilter, &'static str> {
		// Use helper functions to simplify the conversion process
		let about = Address::from_slice(&Self::decode_hex_to_bytes(&self.about)?);
		let key = Self::parse_bytes32(&self.key)?;
		let sig_r = Self::parse_bytes32(&self.sig_r)?;
		let sig_s = Self::parse_bytes32(&self.sig_s)?;
		let rec_id = Self::parse_u8(&self.rec_id)?;
		let value = Self::parse_u8(&self.value)?;
		let message = Self::parse_bytes32(&self.message)?;

		// Construct AttestationPayload and serialize it
		let payload = AttestationPayload::new(sig_r, sig_s, rec_id, value, message);
		let val = Bytes::from(payload.to_bytes());

		// Recover the signature
		let attestation =
			Attestation::new(about, H256::from(key), value, Some(H256::from(message)));
		let att_fr = attestation.to_attestation_fr().unwrap();
		let recoverable_sig = payload.get_signature();

		let signed_att = SignedAttestation::new(att_fr, recoverable_sig);
		let creator = address_from_signed_att(&signed_att).unwrap();

		Ok(AttestationCreatedFilter { about, key, val, creator })
	}

	// Helper function for decoding hexadecimal string into a byte array
	fn decode_hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, &'static str> {
		hex::decode(&hex_str[2..]).map_err(|_| "Failed to decode hexadecimal string")
	}

	// Helper function for encoding byte array into hexadecimal string
	fn encode_bytes_to_hex(bytes: &[u8]) -> String {
		format!("0x{}", hex::encode(bytes))
	}

	// Helper function for parsing string into a byte array
	fn parse_bytes32(hex_str: &str) -> Result<[u8; 32], &'static str> {
		let bytes = Self::decode_hex_to_bytes(hex_str)?;
		let bytes_array: [u8; 32] =
			bytes.try_into().map_err(|_| "Failed to convert into byte array")?;
		Ok(bytes_array)
	}

	// Helper function for parsing string into u8
	fn parse_u8(value: &str) -> Result<u8, &'static str> {
		value.parse::<u8>().map_err(|_| "Failed to parse into u8")
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
