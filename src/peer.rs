use std::collections::HashMap;

const DELTA: f64 = 0.001;

pub type PeerIndex = u32;
pub type PeerScore = f64;

#[derive(Clone, Debug)]
pub struct Peer {
    index: PeerIndex,
    local_trust_values: HashMap<PeerIndex, PeerScore>,
    ti: PeerScore,
    last_cij_ti: HashMap<PeerIndex, PeerScore>,
    is_converged: bool,
}

impl Peer {
    pub fn new(index: PeerIndex) -> Self {
        Self {
            index,
            local_trust_values: HashMap::new(),
            last_cij_ti: HashMap::new(),
            ti: 0.,
            is_converged: false
        }
    }

    pub fn add_neighbor(&mut self, peer: Peer, local_trust_value: PeerScore, pretrust_value: PeerScore){
        self.local_trust_values.insert(peer.index, local_trust_value);
        self.last_cij_ti.insert(peer.index, pretrust_value);
    }

    pub fn heartbeat(&mut self, neighbors: &Vec<Peer>) {
        if self.is_converged {
            return;
        }

        let mut new_ti = 0.;
        for (j, neighbor_j) in neighbors.iter().enumerate() {
            if self.index == j as u32 {
                continue;
            }
            if !neighbor_j.last_cij_ti.contains_key(&self.index) {
                continue;
            }

            // Compute `t_i(k+1) = (1 - a)*(c_1i*t_1(k) + c_ji*t_z(k) + ... + c_ni*t_n(k)) + a*p_i`
            new_ti += neighbor_j.last_cij_ti[&self.index];
        }

        // Send c_ij * t_i(k+1)to all peers j
        for j in 0..neighbors.len() {
            let ju32 = j as u32;
            if self.index == ju32 {
                continue;
            }
            self.last_cij_ti.insert(ju32, self.local_trust_values[&ju32] * new_ti);
        }

        let diff = (new_ti - self.ti).abs();
        if diff <= DELTA {
            self.is_converged = true;
        }

        self.ti = new_ti;
    }

    pub fn is_converged(&self) -> bool {
        self.is_converged
    }

    pub fn get_ti(&self) -> PeerScore {
        self.ti
    }

    pub fn get_index(&self) -> PeerIndex {
        self.index
    }

    pub fn get_local_trust_values(&self) -> &HashMap<PeerIndex, PeerScore> {
        &self.local_trust_values
    }

    pub fn get_last_cij_ti(&self) -> &HashMap<PeerIndex, PeerScore> {
        &self.last_cij_ti
    }
}