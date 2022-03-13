mod network;
mod peer;

use peer::PeerIndex;
use network::{generate_trust_matrix, Network};
use rand::thread_rng;

fn main() {
    let num_peers: PeerIndex = 4;
    let initial_trust_scores = vec![1f64 / num_peers as f64; num_peers as usize];
    dbg!(initial_trust_scores.clone());

    let rng = &mut thread_rng();

    let mc = generate_trust_matrix(num_peers, rng);

    let mut network = Network::new(num_peers, initial_trust_scores);

    network.connect_peers(mc);

    while !network.is_converged() {
        network.tick(rng);
    }

    let global_trust_scores = network.get_global_trust_scores();

    println!("{:?}", global_trust_scores);
}
