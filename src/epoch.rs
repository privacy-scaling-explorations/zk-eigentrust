use std::{time::{UNIX_EPOCH, SystemTime}, fmt::{Display, Formatter, Result as FmtResult}};

use crate::EigenError;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Epoch(pub u64);

impl Display for Epoch {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		write!(f, "Epoch({})", self.0)
	}
}

impl Epoch {
	pub fn to_be_bytes(&self) -> [u8; 8] {
		self.0.to_be_bytes()
	}

	pub fn current_epoch(interval: u64) -> Self {
		let unix_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

		let current_epoch = unix_timestamp.as_secs() / interval;

		Epoch(current_epoch)
	}

	pub fn secs_until_next_epoch(interval: u64) -> u64 {
		let unix_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

		let current_epoch = unix_timestamp.as_secs() / interval;
		let secs_until_next_epoch = (current_epoch + 1) * interval - unix_timestamp.as_secs();

		secs_until_next_epoch
	}

	pub fn current_timestamp() -> u64 {
		let unix_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

		unix_timestamp.as_secs()
	}

	pub fn previous(&self) -> Self {
		Epoch(self.0 - 1)
	}

	pub fn next(&self) -> Self {
		Epoch(self.0 + 1)
	}
}