use std::{
	fmt::{Display, Formatter, Result as FmtResult},
	time::{SystemTime, UNIX_EPOCH},
};

use crate::EigenError;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Epoch(pub u64);

impl Display for Epoch {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		write!(f, "Epoch({})", self.0)
	}
}

impl Epoch {
	pub fn to_be_bytes(self) -> [u8; 8] {
		self.0.to_be_bytes()
	}

	pub fn from_be_bytes(bytes: [u8; 8]) -> Result<Self, EigenError> {
		Ok(Epoch(u64::from_le_bytes(bytes)))
	}

	pub fn current_epoch(interval: u64) -> Result<Self, EigenError> {
		let unix_timestamp = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map_err(|_| EigenError::EpochError)?;

		let current_epoch = unix_timestamp.as_secs() / interval;

		Ok(Epoch(current_epoch))
	}

	pub fn secs_until_next_epoch(interval: u64) -> Result<u64, EigenError> {
		let unix_timestamp = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map_err(|_| EigenError::EpochError)?;

		let current_epoch = unix_timestamp.as_secs() / interval;
		let secs_until_next_epoch = (current_epoch + 1) * interval - unix_timestamp.as_secs();

		Ok(secs_until_next_epoch)
	}

	pub fn current_timestamp() -> Result<u64, EigenError> {
		let unix_timestamp = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map_err(|_| EigenError::EpochError)?;

		Ok(unix_timestamp.as_secs())
	}

	pub fn previous(&self) -> Self {
		Epoch(self.0 - 1)
	}

	pub fn next(&self) -> Self {
		Epoch(self.0 + 1)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_epoch_to_be_bytes() {
		let epoch = Epoch(0);
		let expected = [0, 0, 0, 0, 0, 0, 0, 0];
		let actual = epoch.to_be_bytes();
		assert_eq!(expected, actual);
	}

	#[test]
	fn test_epoch_current_epoch() {
		let interval = 10;
		let epoch = Epoch::current_epoch(interval).unwrap();

		let unix_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

		let expected = Epoch(unix_timestamp.as_secs() / interval);

		assert_eq!(expected, epoch);
	}

	#[test]
	fn test_epoch_secs_until_next_epoch() {
		let interval = 10;
		let secs_until_next_epoch = Epoch::secs_until_next_epoch(interval).unwrap();

		let unix_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

		let current_epoch = unix_timestamp.as_secs() / interval;
		let expected = (current_epoch + 1) * interval - unix_timestamp.as_secs();

		assert_eq!(expected, secs_until_next_epoch);
	}
}
