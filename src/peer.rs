use std::collections::HashMap;

const DELTA: f64 = 0.001;

pub type PeerIndex = u32;
pub type PeerScore = f64;

#[derive(Clone, Debug)]
pub struct Peer {
    index: PeerIndex,
    local_trust_values: HashMap<PeerIndex, PeerScore>,
    ti: PeerScore,
    is_converged: bool,
}

impl Peer {
    pub fn new(index: PeerIndex, initial_ti: PeerScore) -> Self {
        Self {
            index,
            local_trust_values: HashMap::new(),
            ti: initial_ti,
            is_converged: false
        }
    }

    pub fn add_neighbour(&mut self, peer: Peer, local_trust_value: PeerScore){
        self.local_trust_values.insert(peer.index, local_trust_value);
    }

    pub fn heartbeat(&mut self, neighbours: &Vec<Peer>) {
        if self.is_converged {
            return;
        }

        let mut new_ti = 0.;
        for (j, neighbour_j) in neighbours.iter().enumerate() {
            if self.index == j as u32 {
                continue;
            }

            // Compute `t_i(k+1) = (1 - a)*(c_1i*t_1(k) + c_ji*t_z(k) + ... + c_ni*t_n(k)) + a*p_i`
            // We are going through each neighbour and calculating their local trust towards peer i,
            // multiplied by that neighbour's trust score.
            // This means that neighbour's opinion about peer i is weighted by their trust score.
            // If neighbour has a low trust score (is not trusted by the network), their opinion is
            // not taken seriously, compared to neighbours with a high trust score. 
            new_ti += neighbour_j.get_local_trust_value(self.index) * neighbour_j.get_ti();
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

    pub fn get_local_trust_value(&self, i: PeerIndex) -> PeerScore {
        self.local_trust_values[&i]
    }
}