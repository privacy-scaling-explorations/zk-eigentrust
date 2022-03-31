use eigen_trust::{network::{Network, NetworkConfig}, peer::PeerConfig};
use rand::thread_rng;
use eigen_trust::utils::generate_trust_matrix;

#[derive(Clone, Copy, Debug)]
struct Peer;
impl PeerConfig for Peer {
	type Index = usize;
	type Score = f64;
}

struct Network4Config;
impl NetworkConfig for Network4Config {
	type Peer = Peer;
	const DELTA: f64 = 0.001;
	const SIZE: usize = 4;
	const MAX_ITERATIONS: usize = 1000;
}

#[test]
fn simulate_conversion_4_peers() {
	let rng = &mut thread_rng();
	let num_peers: usize = Network4Config::SIZE;

    let initial_trust_scores = vec![1f64 / num_peers as f64; num_peers as usize];
    let mc: Vec<Vec<f64>> = generate_trust_matrix(num_peers, rng);

    let mut network = Network::<Network4Config>::bootstrap(initial_trust_scores, mc);

    network.converge(rng);

    let global_trust_scores = network.get_global_trust_scores();

	println!("is_converged: {}", network.is_converged());
    println!("{:?}", global_trust_scores);
}