use std::{collections::HashMap, fmt::Debug};
use std::hash::Hash;
use num::{Float, Zero, NumCast};

pub trait PeerConfig: Clone {
	type Index: From<usize> + Eq + Hash + Clone;
	type Score: Float + Debug;
}

#[derive(Clone, Debug)]
pub struct Peer<C: PeerConfig> {
    index: C::Index,
    local_trust_values: HashMap<C::Index, C::Score>,
    ti: C::Score,
    is_converged: bool,
}

impl<C: PeerConfig> Peer<C> {
    pub fn new(index: C::Index, initial_ti: C::Score) -> Self {
        Self {
            index,
            local_trust_values: HashMap::new(),
            ti: initial_ti,
            is_converged: false,
        }
    }

    pub fn add_neighbor(&mut self, peer: Peer<C>, local_trust_value: C::Score) {
        self.local_trust_values
            .insert(peer.index, local_trust_value);
    }

    pub fn heartbeat(&mut self, neighbors: &Vec<Peer<C>>, delta: f64) {
        if self.is_converged {
            return;
        }

        let mut new_ti = C::Score::zero();
        for neighbor_j in neighbors.iter() {
            if &self.index == neighbor_j.get_index() {
                continue;
            }

            // Compute `t_i(k+1) = (1 - a)*(c_1i*t_1(k) + c_ji*t_z(k) + ... + c_ni*t_n(k)) + a*p_i`
            // We are going through each neighbor and taking their local trust towards peer `i`,
            // and multiplying it by that neighbor's global trust score.
            // This means that neighbors' opinion about peer i is weighted by their global trust score.
            // If a neighbor has a low trust score (is not trusted by the network),
            // their opinion is not taken seriously, compared to neighbors with a high trust score.
            new_ti = new_ti + neighbor_j.get_local_trust_value(&self.index) * neighbor_j.get_ti();
        }

        let diff = (new_ti - self.ti).abs();
        if diff <= <C::Score as NumCast>::from(delta).unwrap() {
            self.is_converged = true;
        }

        self.ti = new_ti;
    }

    pub fn is_converged(&self) -> bool {
        self.is_converged
    }

    pub fn get_ti(&self) -> C::Score {
        self.ti
    }

	pub fn get_index(&self) -> &C::Index {
        &self.index
    }

    pub fn get_local_trust_value(&self, i: &C::Index) -> C::Score {
        self.local_trust_values[i]
    }
}
