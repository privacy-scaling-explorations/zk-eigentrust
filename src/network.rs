use rand::{RngCore, prelude::SliceRandom};
use rand::Rng;

use crate::peer::{Peer, PeerIndex, PeerScore};

type TMatrix = Vec<Vec<PeerScore>>;
type TVector = Vec<PeerScore>;

pub struct Network {
    peers: Vec<Peer>,
    is_converged: bool,
}

impl Network {
    pub fn new(size: PeerIndex, initial_trust_scores: TVector) -> Self {
        let peers = (0..size).map(|x| Peer::new(x, initial_trust_scores[x as usize])).collect();
        Self {
            peers,
            is_converged: false,
        }
    }

    pub fn connect_peers(&mut self, local_trust_matrix: TMatrix) {
        for (i, c_i) in local_trust_matrix.iter().enumerate() {
            for (j, c_ij) in c_i.iter().enumerate() {
                if i == j {
                    continue;
                }

                let peer_j = self.peers[j].clone();
                self.peers[i].add_neighbour(peer_j, *c_ij);
            }
        }
    }

    pub fn tick<R: RngCore>(&mut self, rng: &mut R) {
        let mut temp_peers = self.peers.clone();
        // temp_peers.shuffle(rng);

        let mut is_converged = true;
        for peer in temp_peers.iter_mut() {
            peer.heartbeat(&self.peers);
            is_converged = is_converged && peer.is_converged();
        }
        self.peers = temp_peers;
        self.is_converged = is_converged;
    }

    pub fn get_global_trust_scores(&self) -> TVector {
        let mut sum = 0.;
        for peer in self.peers.iter() {
            sum += peer.get_ti();
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

pub fn generate_trust_matrix<R: Rng>(num_peers: PeerIndex, rng: &mut R) -> TMatrix {
    let mut matrix = Vec::new();
    for i in 0..num_peers {
        let vals: Vec<PeerScore> = (0..num_peers - 1).map(|_| rng.gen_range(0.0..32.)).collect();
        let sum: PeerScore = vals.iter().sum();

        let mut normalized: Vec<PeerScore> = vals.iter().map(|x| x / sum).collect();

        normalized.insert(i as usize, 0.);

        matrix.push(normalized);
    }

    matrix
}