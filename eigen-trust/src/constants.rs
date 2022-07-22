/// The number of neighbors the peer can have.
/// This is also the maximum number of peers that can be connected to the
/// node.
pub const MAX_NEIGHBORS: usize = 256;
/// Minimum score a peer can have.
pub const MIN_SCORE: f64 = 0.1;
/// List of predetermened bootstrap peers.
pub const BOOTSTRAP_PEERS: [&str; NUM_BOOTSTRAP_PEERS] = ["0x1", "0x2", "0x3", "0x4", "0x5"];
/// The number of bootstrap peers.
pub const NUM_BOOTSTRAP_PEERS: usize = 5;
/// The score of a bootstrap peer.
pub const BOOTSTRAP_SCORE: f64 = 0.5;
/// The genesis epoch.
pub const GENESIS_EPOCH: u64 = 1234;
