#[cfg(feature = "prod")]
mod consts {
	/// The number of neighbors the peer can have.
	/// This is also the maximum number of peers that can be connected to the
	/// node.
	pub const MAX_NEIGHBORS: usize = 256;
	/// List of predetermened bootstrap peers.
	pub const BOOTSTRAP_PEERS: [&str; NUM_BOOTSTRAP_PEERS] = [
		"52RwQpZ9kUDsNi9R8f5FMD27pqyTPB39hQKYeH7fH99P",
		"HhfwhxzwKvS8UGVvfnyJUiA1uL1VhXXfqFWh4BtEM9zx",
		"5vnn3M32KhDE9qsvWGbSy8H59y6Kf64TKmqLeRxKwn6t",
		"3BGPsex45AHQHuJfkfWkMfKHcwNjYcXhC3foH77kurPX",
		"2hfQezShegBrascTTkbCjPzbLZSq6KADnkZbBjQ2uaih",
	];
	/// The number of bootstrap peers.
	pub const NUM_BOOTSTRAP_PEERS: usize = 5;
	/// The score of a bootstrap peer.
	pub const BOOTSTRAP_SCORE: f64 = 0.5;
	/// Number of iterations to loop in each epoch.
	pub const NUM_ITERATIONS: u32 = 10;
	/// Epoch duration in seconds
	pub const EPOCH_INTERVAL: u64 = 60 * 60; // One hour
	/// Iteration duration in seconds
	pub const ITER_INTERVAL: u64 = 20;
}

#[cfg(not(feature = "prod"))]
#[allow(missing_docs)]
mod consts {
	pub const MAX_NEIGHBORS: usize = 12;
	pub const BOOTSTRAP_PEERS: [&str; NUM_BOOTSTRAP_PEERS] = [
		"52RwQpZ9kUDsNi9R8f5FMD27pqyTPB39hQKYeH7fH99P",
		"HhfwhxzwKvS8UGVvfnyJUiA1uL1VhXXfqFWh4BtEM9zx",
		"5vnn3M32KhDE9qsvWGbSy8H59y6Kf64TKmqLeRxKwn6t",
		"3BGPsex45AHQHuJfkfWkMfKHcwNjYcXhC3foH77kurPX",
		"2hfQezShegBrascTTkbCjPzbLZSq6KADnkZbBjQ2uaih",
	];
	pub const NUM_BOOTSTRAP_PEERS: usize = 5;
	pub const BOOTSTRAP_SCORE: f64 = 0.5;
	pub const NUM_ITERATIONS: u32 = 6;
	pub const EPOCH_INTERVAL: u64 = 100;
	pub const ITER_INTERVAL: u64 = 10;
}

pub use consts::*;
