use csv::Reader as CsvReader;
use serde::de::DeserializeOwned;
use std::{
	env,
	fs::File,
	io::{BufReader, Error},
	path::Path,
};

/// Reads the json file and deserialize it into the provided type
pub fn read_csv_file<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<Vec<T>, Error> {
	let path = path.as_ref();
	let file = File::open(path)?;
	let file = BufReader::new(file);
	let mut reader = CsvReader::from_reader(file);
	let mut records = Vec::new();
	for result in reader.deserialize() {
		let record: T = result?;
		records.push(record);
	}
	Ok(records)
}

/// Reads the json file and deserialize it into the provided type
pub fn read_csv_data<T: DeserializeOwned>(file_name: &str) -> Result<Vec<T>, Error> {
	let current_dir = env::current_dir().unwrap();
	let path = current_dir.join(format!("../data/{}.csv", file_name));
	let file = File::open(path)?;
	let file = BufReader::new(file);
	let mut reader = CsvReader::from_reader(file);
	let mut records = Vec::new();
	for result in reader.deserialize() {
		let record: T = result?;
		records.push(record);
	}
	Ok(records)
}
