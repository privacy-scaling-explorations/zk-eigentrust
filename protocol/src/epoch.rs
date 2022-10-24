//! The module for epoch related calculatioins, like:
//! - Creating an epoch struct
//! - Seconds until next epoch
//! - Current epoch
//! - Current timestamp

use std::{
	fmt::{Display, Formatter, Result as FmtResult},
	time::{SystemTime, UNIX_EPOCH},
};

/// Epoch struct, which is a wrapper around epoch number and timestamp.
// TODO: add epoch_number and timestamp as private fields
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Epoch(pub u64);

impl Display for Epoch {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		write!(f, "Epoch({})", self.0)
	}
}

impl Epoch {
	/// Returns epoch number as bytes.
	pub fn to_be_bytes(self) -> [u8; 8] {
		self.0.to_be_bytes()
	}

	/// Constructs the Epoch from bytes
	pub fn from_be_bytes(b: [u8; 8]) -> Self {
		Epoch(u64::from_be_bytes(b))
	}

	/// Calculates the current epoch number based on the interval duration.
	pub fn current_epoch(interval: u64) -> Self {
		let secs = Self::current_timestamp();

		let current_epoch = secs / interval;

		Epoch(current_epoch)
	}

	/// Calculates the seconds until the next epoch based on the interval
	/// duration.
	pub fn secs_until_next_epoch(interval: u64) -> u64 {
		let secs = Self::current_timestamp();
		let current_epoch = Self::current_epoch(interval);
		(current_epoch.0 + 1) * interval - secs
	}

	/// Calculates the current timestamp. The difference between UNIX timestamp
	/// start and now.
	pub fn current_timestamp() -> u64 {
		let unix_timestamp =
			SystemTime::now().duration_since(UNIX_EPOCH).expect("SystemTime Error - Unix time");
		unix_timestamp.as_secs()
	}

	/// Returns previous epoch.
	pub fn previous(&self) -> Self {
		Epoch(self.0 - 1)
	}

	/// Returns next epoch.
	pub fn next(&self) -> Self {
		Epoch(self.0 + 1)
	}

	/// Check if epoch is zero.
	pub fn is_zero(&self) -> bool {
		self.0 == 0
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn epoch_display() {
		let epoch = format!("{}", Epoch(123));
		assert_eq!(epoch, "Epoch(123)");
	}

	#[test]
	fn epoch_test_next_previous() {
		let epoch = Epoch(1);
		assert_eq!(epoch.next(), Epoch(2));
		assert_eq!(epoch.previous(), Epoch(0));
	}

	#[test]
	fn epoch_to_be_bytes() {
		let epoch = Epoch(0);
		let expected = [0, 0, 0, 0, 0, 0, 0, 0];
		let actual = epoch.to_be_bytes();
		assert_eq!(expected, actual);
	}

	#[test]
	fn epoch_current() {
		let interval = 10;
		let epoch = Epoch::current_epoch(interval);

		let unix_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

		let expected = Epoch(unix_timestamp.as_secs() / interval);

		assert_eq!(expected, epoch);
	}

	#[test]
	fn epoch_secs_until_next() {
		let interval = 10;
		let secs_until_next_epoch = Epoch::secs_until_next_epoch(interval);

		let unix_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

		let current_epoch = unix_timestamp.as_secs() / interval;
		let expected = (current_epoch + 1) * interval - unix_timestamp.as_secs();

		assert_eq!(expected, secs_until_next_epoch);
	}

	#[test]
	fn epoch_current_timestamp() {
		let timestamp = Epoch::current_timestamp();

		let unix_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

		assert_eq!(unix_timestamp.as_secs(), timestamp);
	}
}
