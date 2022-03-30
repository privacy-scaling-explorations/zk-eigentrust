use eigen_trust::network::{Network, NetworkConfig};
use rand::thread_rng;
use eigen_trust::utils::generate_trust_matrix;

struct Network4Config;
impl NetworkConfig for Network4Config {
	type PeerIndex = usize;
	type PeerScore = f64;
	const DELTA: f64 = 0.001;
}

#[test]
fn simulate_conversion_4_peers() {
	let num_peers: usize = 4;
    let initial_trust_scores = vec![1f64 / num_peers as f64; num_peers as usize];

    let rng = &mut thread_rng();

    let mc: Vec<Vec<f64>> = generate_trust_matrix(num_peers, rng);

    let mut network = Network::<Network4Config>::new(num_peers, initial_trust_scores);

    network.connect_peers(mc);

    while !network.is_converged() {
        network.tick(rng);
    }

    let global_trust_scores = network.get_global_trust_scores();

    println!("{:?}", global_trust_scores);
}