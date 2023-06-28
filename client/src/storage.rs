//! # Storage Module.
//!
//! This module contains generic storage traits and implementations.

use serde::{de::DeserializeOwned, Serialize};

use crate::utils::{create_csv_file, read_csv_file};
use std::marker::PhantomData;

/// The main trait to be implemented by different storage types.
pub trait Storage<T> {
	/// Loads data from storage.
	fn load(&self) -> Result<T, &'static str>;
	/// Saves data to storage.
	fn save(&mut self, data: T) -> Result<(), &'static str>;
}

/// Memory data storage.
pub struct MemoryStorage<T> {
	data: T,
}

impl<T: Clone> MemoryStorage<T> {
	/// Creates a new MemoryStorage
	pub fn new(data: T) -> Self {
		Self { data }
	}
}

impl<T: Clone> Storage<T> for MemoryStorage<T> {
	fn load(&self) -> Result<T, &'static str> {
		Ok(self.data.clone())
	}

	fn save(&mut self, data: T) -> Result<(), &'static str> {
		self.data = data;
		Ok(())
	}
}

/// File data storage.
pub struct FileStorage<T> {
	filepath: String,
	phantom: PhantomData<T>,
}

impl<T> FileStorage<T> {
	/// Create a new FileStorage
	pub fn new(filepath: String) -> Self {
		Self { filepath, phantom: PhantomData }
	}
}

impl Storage<Vec<Vec<String>>> for FileStorage<Vec<Vec<String>>> {
	fn load(&self) -> Result<Vec<Vec<String>>, &'static str> {
		read_csv_file(&self.filepath)
	}

	fn save(&mut self, data: Vec<Vec<String>>) -> Result<(), &'static str> {
		create_csv_file(&self.filepath, data)
	}
}

impl<T: Serialize + DeserializeOwned> Storage<Vec<T>> for FileStorage<T> {
	fn load(&self) -> Result<Vec<T>, &'static str> {
		read_csv_file(&self.filepath)
	}

	fn save(&mut self, data: Vec<T>) -> Result<(), &'static str> {
		todo!();
	}
}

/// Database storage.
pub struct DatabaseStorage<T> {
	url: String,
	phantom: PhantomData<T>,
}

impl<T> DatabaseStorage<T> {
	/// Creates a new DatabaseStorage.
	pub fn new(url: String) -> Self {
		Self { url, phantom: PhantomData }
	}
}

impl<T> Storage<T> for DatabaseStorage<T> {
	fn load(&self) -> Result<T, &'static str> {
		todo!()
	}

	fn save(&mut self, data: T) -> Result<(), &'static str> {
		todo!()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;

	#[test]
	fn test_create_and_read_csv() {
		// Create the file storage
		let filename = "test";
		let mut file_storage = FileStorage::new(filename.to_string());

		// Prepare the data to save
		let content = vec![
			vec!["peer_address".to_string(), "score".to_string()],
			vec!["0x70997970c51812dc3a010c7d01b50e0d17dc7666".to_string(), "1000".to_string()],
		];

		// Save the data
		assert!(file_storage.save(content).is_ok());

		// Load the data
		let result = file_storage.load();

		// Assert
		assert!(result.is_ok());
		let records: Vec<Vec<String>> = result.unwrap();
		assert_eq!(records.len(), 1);
		assert_eq!(
			records[0],
			vec!["0x70997970c51812dc3a010c7d01b50e0d17dc7666".to_string(), "1000".to_string()]
		);

		// Clean up
		let file_path = format!("../data/{}.csv", filename);
		fs::remove_file(file_path).unwrap();
	}
}
