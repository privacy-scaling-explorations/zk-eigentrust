use num::One;
use num::{Float, NumCast, Zero};
use std::hash::Hash;
use std::{collections::HashMap, fmt::Debug};

pub trait PeerConfig: Clone {
    type Index: From<usize> + Eq + Hash + Clone;
    type Score: Float + Debug;
}

#[derive(Clone, Debug)]
pub struct Peer<C: PeerConfig> {
    index: C::Index,
    local_trust_scores: HashMap<C::Index, C::Score>,
    global_trust_score: C::Score,
    pre_trust_score: C::Score,
    is_converged: bool,
}

impl<C: PeerConfig> Peer<C> {
    pub fn new(index: C::Index, global_trust_score: C::Score, pre_trust_score: C::Score) -> Self {
        Self {
            index,
            local_trust_scores: HashMap::new(),
            global_trust_score,
            pre_trust_score,
            is_converged: false,
        }
    }

    pub fn add_neighbor(&mut self, peer_index: C::Index, local_trust_value: C::Score) {
        self.local_trust_scores
            .insert(peer_index, local_trust_value);
    }

    pub fn heartbeat(&mut self, neighbors: &Vec<Peer<C>>, delta: f64, pre_trust_weight: f64) {
        if self.is_converged {
            return;
        }

        let pre_trust_weight_casted = <C::Score as NumCast>::from(pre_trust_weight).unwrap();

        let mut new_global_trust_score = C::Score::zero();
        for neighbor_j in neighbors.iter() {
            if self.index == neighbor_j.get_index() {
                continue;
            }

            // Compute `t_i(k+1) = (1 - a)*(c_1i*t_1(k) + c_ji*t_z(k) + ... + c_ni*t_n(k)) + a*p_i`
            // We are going through each neighbor and taking their local trust towards peer `i`,
            // and multiplying it by that neighbor's global trust score.
            // This means that neighbors' opinion about peer i is weighted by their global trust score.
            // If a neighbor has a low trust score (is not trusted by the network),
            // their opinion is not taken seriously, compared to neighbors with a high trust score.
            let neighbor_opinion =
                neighbor_j.get_local_trust_score(&self.index) * neighbor_j.get_global_trust_score();
            let new_score = new_global_trust_score + neighbor_opinion;
            let new_weighted_score = (C::Score::one() - self.pre_trust_score) * new_score
                + pre_trust_weight_casted * self.pre_trust_score;

            new_global_trust_score = new_weighted_score;
        }

        let diff = (new_global_trust_score - self.global_trust_score).abs();
        if diff <= <C::Score as NumCast>::from(delta).unwrap() {
            self.is_converged = true;
        }

        self.global_trust_score = new_global_trust_score;
    }

    pub fn is_converged(&self) -> bool {
        self.is_converged
    }

    pub fn get_global_trust_score(&self) -> C::Score {
        self.global_trust_score
    }

    pub fn get_pre_trust_score(&self) -> C::Score {
        self.pre_trust_score
    }

    pub fn get_index(&self) -> C::Index {
        self.index.clone()
    }

    pub fn get_local_trust_score(&self, i: &C::Index) -> C::Score {
        self.local_trust_scores[i]
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Clone, Debug, PartialEq)]
    struct TestConfig {
        index: usize,
        score: f64,
    }

    impl PeerConfig for TestConfig {
        type Index = usize;
        type Score = f64;
    }

    #[test]
    fn test_peer_new() {
        let mut peer = Peer::<TestConfig>::new(0, 0.0, 0.4);
        peer.add_neighbor(1, 0.5);
        assert_eq!(peer.get_index(), 0);
        assert_eq!(peer.get_pre_trust_score(), 0.4);
        assert_eq!(peer.get_global_trust_score(), 0.0);
        assert_eq!(peer.get_local_trust_score(&1), 0.5);
    }
}
