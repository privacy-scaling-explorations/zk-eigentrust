use super::IVP;
use crate::constants::MAX_NEIGHBORS;
use eigen_trust_circuit::halo2wrong::curves::{bn256::Fr as Bn256Scalar, group::ff::PrimeField};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignatureData {
	pub(crate) sk: [u8; 32],
	pub(crate) pk: [u8; 32],
	pub(crate) neighbours: Vec<[u8; 32]>,
	pub(crate) scores: Vec<f64>,
}

pub struct Signature {
	pub(crate) sk: Bn256Scalar,
	pub(crate) pk: Bn256Scalar,
	pub(crate) neighbours: [Option<Bn256Scalar>; MAX_NEIGHBORS],
	pub(crate) scores: [f64; MAX_NEIGHBORS],
}

impl Signature {
	pub fn new(
		sk: Bn256Scalar, pk: Bn256Scalar, neighbours: [Option<Bn256Scalar>; MAX_NEIGHBORS],
		scores: [f64; MAX_NEIGHBORS],
	) -> Self {
		Self { sk, pk, neighbours, scores }
	}

	pub fn empty() -> Self {
		let sk = Bn256Scalar::zero();
		let pk = Bn256Scalar::zero();
		let neighbours = [None; MAX_NEIGHBORS];
		let scores = [0.; MAX_NEIGHBORS];
		Self { sk, pk, neighbours, scores }
	}
}

impl From<SignatureData> for Signature {
	fn from(sig: SignatureData) -> Self {
		let sk = Bn256Scalar::from_repr(sig.sk).unwrap();
		let pk = Bn256Scalar::from_repr(sig.pk).unwrap();
		let mut neighbours = [None; MAX_NEIGHBORS];
		let mut scores = [0.; MAX_NEIGHBORS];
		for (i, n) in sig.neighbours.iter().enumerate().take(MAX_NEIGHBORS) {
			neighbours[i] = Some(Bn256Scalar::from_repr(*n).unwrap());
		}
		for (i, n) in sig.scores.iter().enumerate().take(MAX_NEIGHBORS) {
			scores[i] = *n;
		}

		Signature { sk, pk, neighbours, scores }
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn sig_empty_sig() {
		let empty_sig = Signature::empty();
		assert_eq!(empty_sig.pk, Bn256Scalar::zero());
		assert_eq!(empty_sig.sk, Bn256Scalar::zero());
	}

	#[test]
	fn sig_from_data() {
		let sk = [0; 32];
		let pk = [0; 32];
		let neighbours = vec![[0; 32]];
		let scores = vec![0.];

		let sig_data = SignatureData { sk, pk, neighbours, scores };
		let sig = Signature::from(sig_data);

		assert_eq!(sig.sk, Bn256Scalar::zero());
		assert_eq!(sig.pk, Bn256Scalar::zero());
	}
}
