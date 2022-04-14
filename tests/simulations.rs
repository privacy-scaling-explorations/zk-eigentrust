// Unwrap is allowed while testing
#![allow(clippy::unwrap_used)]

use eigen_trust::{
	network::{Network, NetworkConfig},
	peer::TransactionRating,
};
use rand::{thread_rng, Rng};

#[derive(Debug)]
struct Network16Config;
impl NetworkConfig for Network16Config {
	const DELTA: f64 = 0.0001;
	const MAX_ITERATIONS: usize = 1000;
	const NUM_MANAGERS: u64 = 2;
	const PRETRUST_WEIGHT: f64 = 0.5;
	const SIZE: usize = 16;
}

#[test]
fn simulate_converging_16_peers() {
	let rng = &mut thread_rng();
	let num_peers: usize = Network16Config::SIZE;

	let mut pre_trust_scores = vec![0.0; num_peers];
	pre_trust_scores[0] = 0.25;
	pre_trust_scores[1] = 0.25;
	pre_trust_scores[2] = 0.25;
	pre_trust_scores[3] = 0.25;

	let mut network = Network::<Network16Config>::bootstrap(pre_trust_scores).unwrap();

	// Boost peer 5
	for i in 0..num_peers {
		network
			.mock_transaction(i, 5, TransactionRating::Positive)
			.unwrap();
	}

	network.converge(rng).unwrap();
	let global_trust_scores = network.get_global_trust_scores();
	println!("");
	println!(
		"Global trust scores after round 1: {:?}",
		global_trust_scores
	);

	// Boost peer 6
	for i in 0..num_peers {
		network
			.mock_transaction(i, 6, TransactionRating::Positive)
			.unwrap();
	}

	network.converge(rng).unwrap();
	let global_trust_scores = network.get_global_trust_scores();
	println!("");
	println!(
		"Global trust scores after round 2: {:?}",
		global_trust_scores
	);

	// Boost peer 7
	for i in 0..num_peers {
		network
			.mock_transaction(i, 7, TransactionRating::Positive)
			.unwrap();
	}

	network.converge(rng).unwrap();
	let global_trust_scores = network.get_global_trust_scores();
	println!("");
	println!(
		"Global trust scores after round 3: {:?}",
		global_trust_scores
	);
}

#[derive(Debug)]
struct Network256Config;
impl NetworkConfig for Network256Config {
	const DELTA: f64 = 0.0001;
	const MAX_ITERATIONS: usize = 5000;
	const NUM_MANAGERS: u64 = 2;
	const PRETRUST_WEIGHT: f64 = 0.3;
	const SIZE: usize = 256;
}

#[test]
fn simulate_converging_256_peers() {
	let rng = &mut thread_rng();
	let num_peers: usize = Network256Config::SIZE;

	let num_pre_trusted_peers = 12;
	let defalt_score = 1. / num_pre_trusted_peers as f64;
	let mut pre_trust_scores = vec![0.0; num_peers];
	for i in 0..num_pre_trusted_peers {
		pre_trust_scores[i] = defalt_score;
	}

	let mut network = Network::<Network256Config>::bootstrap(pre_trust_scores).unwrap();

	// Boosting 5 random peers
	for cycle in 0..5 {
		let rnd_index: usize = rng.gen_range(num_pre_trusted_peers..num_peers);
		for i in 0..num_pre_trusted_peers {
			network
				.mock_transaction(i, rnd_index, TransactionRating::Positive)
				.unwrap();
		}

		println!("");
		println!("Boosting {} in cycle: {}", rnd_index, cycle);
		network.converge(rng).unwrap();
		let global_trust_scores = network.get_global_trust_scores();
		println!("{:?}", global_trust_scores);
	}
}
