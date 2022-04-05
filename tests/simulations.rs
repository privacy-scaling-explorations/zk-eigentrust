// Unwrap is allowed while testing
#![allow(clippy::unwrap_used)]

use eigen_trust::{
	network::{Network, NetworkConfig},
	peer::{PeerConfig, TransactionRating},
};
use rand::thread_rng;

#[derive(Clone, Copy, Debug)]
struct Peer;
impl PeerConfig for Peer {
	type Index = usize;
}

struct Network4Config;
impl NetworkConfig for Network4Config {
	type Peer = Peer;

	const DELTA: f64 = 0.001;
	const MAX_ITERATIONS: usize = 1000;
	const PRETRUST_WEIGHT: f64 = 0.5;
	const SIZE: usize = 4;
}

#[test]
fn simulate_converging_4_peers() {
	let rng = &mut thread_rng();
	let num_peers: usize = Network4Config::SIZE;

	let mut pre_trust_scores = vec![0.0; num_peers];
	pre_trust_scores[0] = 0.5;
	pre_trust_scores[1] = 0.5;

	let mut network = Network::<Network4Config>::bootstrap(pre_trust_scores).unwrap();

	// Mock transactions from peer 0 to the rest of the peers.
	network
		.mock_transaction(0, 1, TransactionRating::Positive)
		.unwrap();
	network
		.mock_transaction(0, 2, TransactionRating::Positive)
		.unwrap();
	network
		.mock_transaction(0, 3, TransactionRating::Positive)
		.unwrap();

	// Mock transactions from peer 1 to the rest of the peers.
	network
		.mock_transaction(1, 0, TransactionRating::Positive)
		.unwrap();
	network
		.mock_transaction(1, 2, TransactionRating::Positive)
		.unwrap();
	network
		.mock_transaction(1, 3, TransactionRating::Positive)
		.unwrap();

	// Mock transactions from peer 2 to the rest of the peers.
	network
		.mock_transaction(2, 0, TransactionRating::Positive)
		.unwrap();
	network
		.mock_transaction(2, 1, TransactionRating::Positive)
		.unwrap();
	network
		.mock_transaction(2, 3, TransactionRating::Positive)
		.unwrap();

	network.converge(rng);

	let global_trust_scores = network.get_global_trust_scores();

	println!("is_converged: {}", network.is_converged());
	println!("{:?}", global_trust_scores);
}
