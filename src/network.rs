use crate::peer::{Peer, PeerConfig};
use rand::RngCore;
use num::Zero;
use rand::prelude::SliceRandom;

pub trait NetworkConfig {
	type Peer: PeerConfig;
	const DELTA: f64;
	const SIZE: usize;
	const MAX_ITERATIONS: usize;
}

pub struct Network<C: NetworkConfig> {
    peers: Vec<Peer<C::Peer>>,
	is_converged: bool,
}

impl<C: NetworkConfig> Network<C> {
    pub fn bootstrap(
		initial_trust_scores: Vec<<C::Peer as PeerConfig>::Score>,
		local_trust_matrix: Vec<Vec<<C::Peer as PeerConfig>::Score>>
	) -> Self {
		assert!(initial_trust_scores.len() == C::SIZE);
		assert!(local_trust_matrix.len() == C::SIZE);

		let mut peers = Vec::with_capacity(C::SIZE);
		for x in 0..C::SIZE {
			let index = <C::Peer as PeerConfig>::Index::from(x);
			peers.push(Peer::new(index, initial_trust_scores[x as usize]));
		}

		for (i, c_i) in local_trust_matrix.iter().enumerate() {
			assert!(c_i.len() == C::SIZE);

            for (j, c_ij) in c_i.iter().enumerate() {
                if i == j {
                    continue;
                }

                let peer_j = peers[j].clone();
                peers[i].add_neighbor(peer_j, *c_ij);
            }
        }

        Self {
			peers,
			is_converged: false
		}
    }

    pub fn converge<R: RngCore>(&mut self, rng: &mut R) {
        let mut temp_peers = self.peers.clone();
        temp_peers.shuffle(rng);

		for _ in 0..C::MAX_ITERATIONS {

			let mut is_everyone_converged = true;
			for peer in temp_peers.iter_mut() {
				peer.heartbeat(&self.peers, C::DELTA);
				is_everyone_converged = is_everyone_converged && peer.is_converged();
			}

			if is_everyone_converged {
				self.is_converged = true;
				break;
			}
		}

		self.peers = temp_peers;
    }

    pub fn get_global_trust_scores(&self) -> Vec<<C::Peer as PeerConfig>::Score> {
        let mut sum = <C::Peer as PeerConfig>::Score::zero();
        for peer in self.peers.iter() {
            sum = sum + peer.get_ti();
        }

        let mut ti_vec = Vec::new();
        for peer in self.peers.iter() {
            ti_vec.push(peer.get_ti() / sum);
        }

        ti_vec
    }

    pub fn is_converged(&self) -> bool {
        self.is_converged
    }
}
