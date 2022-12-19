use eigen_trust_circuit::{
	eddsa::native::{PublicKey, SecretKey, Signature},
	halo2wrong::curves::{bn256::Fr as Scalar, group::ff::PrimeField, FieldExt},
};
use serde::{Deserialize, Serialize};

use super::NUM_NEIGHBOURS;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttestationData {
	sig_r_x: [u8; 32],
	sig_r_y: [u8; 32],
	sig_s: [u8; 32],
	pk: [[u8; 32]; 2],
	neighbours: Vec<[[u8; 32]; 2]>,
	scores: Vec<[u8; 32]>,
}

impl From<Attestation> for AttestationData {
	fn from(att: Attestation) -> Self {
		let sig_r_x = att.sig.big_r.x.to_bytes();
		let sig_r_y = att.sig.big_r.y.to_bytes();
		let sig_s = att.sig.s.to_bytes();
		let pk_bytes = att.pk.to_raw();
		let neighbours = att
			.neighbours
			.map(|x| x.map_or(PublicKey::default().to_raw(), |v| v.to_raw()))
			.to_vec();
		let scores =
			att.scores.map(|x| x.map_or(Scalar::zero().to_bytes(), |v| v.to_bytes())).to_vec();

		Self { sig_r_x, sig_r_y, sig_s, pk: pk_bytes, neighbours, scores }
	}
}

#[derive(Clone)]
pub struct Attestation {
	pub(crate) sig: Signature,
	pub(crate) pk: PublicKey,
	pub(crate) neighbours: [Option<PublicKey>; NUM_NEIGHBOURS],
	pub(crate) scores: [Option<Scalar>; NUM_NEIGHBOURS],
}

impl Attestation {
	pub fn new(
		sig: Signature, pk: PublicKey, neighbours: [Option<PublicKey>; NUM_NEIGHBOURS],
		scores: [Option<Scalar>; NUM_NEIGHBOURS],
	) -> Self {
		Self { sig, pk, neighbours, scores }
	}
}

impl From<AttestationData> for Attestation {
	fn from(att: AttestationData) -> Self {
		let pk = PublicKey::from_raw(att.pk);
		let sig_r_x = Scalar::from_bytes(&att.sig_r_x).unwrap();
		let sig_r_y = Scalar::from_bytes(&att.sig_r_y).unwrap();
		let sig_s = Scalar::from_bytes(&att.sig_s).unwrap();
		let sig = Signature::new(sig_r_x, sig_r_y, sig_s);

		let mut neighbours = [(); NUM_NEIGHBOURS].map(|_| None);
		let mut scores = [None; NUM_NEIGHBOURS];
		for (i, n) in att.neighbours.iter().enumerate().take(NUM_NEIGHBOURS) {
			neighbours[i] = Some(PublicKey::from_raw(*n));
		}
		for (i, n) in att.scores.iter().enumerate().take(NUM_NEIGHBOURS) {
			scores[i] = Some(Scalar::from_bytes(n).unwrap());
		}

		Attestation { sig, pk, neighbours, scores }
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn sig_from_data() {
		let pk = [[0; 32]; 2];
		let sig_r_x = [0; 32];
		let sig_r_y = [0; 32];
		let sig_s = [0; 32];
		let neighbours = vec![[[0; 32]; 2]];
		let scores = vec![[0; 32]];

		let att_data = AttestationData {
			sig_r_x,
			sig_r_y,
			sig_s,
			pk,
			neighbours: neighbours.clone(),
			scores: scores.clone(),
		};
		let att = Attestation::from(att_data);

		assert_eq!(att.pk.to_raw(), pk);
		assert_eq!(att.sig.big_r.x.to_bytes(), sig_r_x);
		assert_eq!(att.sig.big_r.y.to_bytes(), sig_r_y);
		assert_eq!(att.sig.s.to_bytes(), sig_s);
		assert_eq!(att.neighbours[0].clone().unwrap().to_raw(), neighbours[0]);
		assert_eq!(att.scores[0].clone().unwrap().to_bytes(), scores[0]);
	}
}
