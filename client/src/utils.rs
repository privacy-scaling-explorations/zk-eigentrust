use csv::{Reader as CsvReader, Writer as CsvWriter};
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

/// Creates new CSV file in the given path and stores the provided data
pub fn create_csv_file<T, U>(filename: &str, content: T) -> Result<(), &'static str>
where
	T: IntoIterator<Item = U>,
	U: AsRef<[u8]>,
{
	let path = format!("../data/{}.csv", filename);

	let mut writer = CsvWriter::from_path(&path).map_err(|_| "Failed to open file")?;

	// Write content
	writer.write_record(content).map_err(|_| "Failed to write record")?;

	// Flush buffer
	writer.flush().map_err(|_| "Failed to flush buffer")?;

	Ok(())
}
