use super::IVP;
use crate::constants::MAX_NEIGHBORS;
use eigen_trust_circuit::{
	eddsa::native::{PublicKey, SecretKey},
	halo2wrong::curves::{bn256::Fr as Scalar, group::ff::PrimeField, FieldExt},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignatureData {
	pub(crate) sk: [[u8; 32]; 2],
	pub(crate) pk: [[u8; 32]; 2],
	pub(crate) neighbours: Vec<[[u8; 32]; 2]>,
	pub(crate) scores: Vec<[u8; 32]>,
}

impl From<Signature> for SignatureData {
	fn from(sig: Signature) -> Self {
		let sk_bytes = sig.sk.to_raw();
		let pk_bytes = sig.pk.to_raw();

		let mut neighbours_bytes = Vec::new();
		sig.neighbours.map(|x_op| x_op.map(|x| neighbours_bytes.push(x.to_raw())));
		let mut scores_bytes = Vec::new();
		sig.scores.map(|x_op| x_op.map(|x| scores_bytes.push(x.to_bytes())));

		SignatureData {
			sk: sk_bytes,
			pk: pk_bytes,
			neighbours: neighbours_bytes,
			scores: scores_bytes,
		}
	}
}

#[derive(Clone)]
pub struct Signature {
	pub(crate) sk: SecretKey,
	pub(crate) pk: PublicKey,
	pub(crate) neighbours: [Option<PublicKey>; MAX_NEIGHBORS],
	pub(crate) scores: [Option<Scalar>; MAX_NEIGHBORS],
}

impl Signature {
	pub fn new(
		sk: SecretKey, pk: PublicKey, neighbours: [Option<PublicKey>; MAX_NEIGHBORS],
		scores: [Option<Scalar>; MAX_NEIGHBORS],
	) -> Self {
		Self { sk, pk, neighbours, scores }
	}
}

impl From<SignatureData> for Signature {
	fn from(sig: SignatureData) -> Self {
		let sk = SecretKey::from_raw(sig.sk);
		let pk = PublicKey::from_raw(sig.pk);
		let mut neighbours = [(); MAX_NEIGHBORS].map(|_| None);
		let mut scores = [None; MAX_NEIGHBORS];
		for (i, n) in sig.neighbours.iter().enumerate().take(MAX_NEIGHBORS) {
			neighbours[i] = Some(PublicKey::from_raw(*n));
		}
		for (i, n) in sig.scores.iter().enumerate().take(MAX_NEIGHBORS) {
			scores[i] = Some(Scalar::from_repr(*n).unwrap());
		}

		Signature { sk, pk, neighbours, scores }
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn sig_from_data() {
		let sk = [[0; 32]; 2];
		let pk = [[0; 32]; 2];
		let neighbours = vec![[[0; 32]; 2]];
		let scores = vec![[0; 32]];

		let sig_data = SignatureData { sk, pk, neighbours, scores };
		let sig = Signature::from(sig_data);

		assert_eq!(sig.sk.to_raw(), sk);
		assert_eq!(sig.pk.to_raw(), pk);
	}
}
