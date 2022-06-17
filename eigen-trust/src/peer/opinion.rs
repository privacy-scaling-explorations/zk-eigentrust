use crate::Epoch;
use super::MAX_NEIGHBORS;

/// The struct for opinions between peers at the specific epoch.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Opinion {
	pub(crate) k: Epoch,
	pub(crate) local_trust_score: f64,
	pub(crate) global_trust_score: f64,
	pub(crate) product: f64,
}

impl Opinion {
	/// Creates a new opinion.
	pub fn new(
		k: Epoch,
		local_trust_score: f64,
		global_trust_score: f64
	) -> Self {
		let product = local_trust_score * global_trust_score;
		Self {
			k,
			local_trust_score,
			global_trust_score,
			product,
		}
	}

	/// Creates an empty opinion, in a case when we don't have any opinion about
	/// a peer, or the neighbor doesn't have any opinion about us.
	pub fn empty(k: Epoch) -> Self {
		Self::new(k, 0.0, 0.0)
	}
}