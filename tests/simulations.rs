use eigen_trust::utils::generate_trust_matrix;
use eigen_trust::{
    network::{Network, NetworkConfig},
    peer::PeerConfig,
};
use rand::thread_rng;

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
    const PRETRUST_WEIGHT: f64 = 0.5;
}

#[test]
fn simulate_conversion_4_peers() {
    let rng = &mut thread_rng();
    let num_peers: usize = Network4Config::SIZE;

    let mut pre_trust_scores = vec![0.0; num_peers];
    pre_trust_scores[0] = 0.5;
    pre_trust_scores[1] = 0.5;

	let default_score = 1. / <<Network4Config as NetworkConfig>::Peer as PeerConfig>::Score::from(num_peers as f64);
    let initial_trust_scores = vec![default_score; num_peers];
    let mc: Vec<Vec<f64>> = generate_trust_matrix(num_peers, rng);

    let mut network =
        Network::<Network4Config>::bootstrap(pre_trust_scores, initial_trust_scores, mc);

    network.converge(rng);

    let global_trust_scores = network.get_global_trust_scores();

    println!("is_converged: {}", network.is_converged());
    println!("{:?}", global_trust_scores);
}
