use crate::circuit::PoseidonNativeSponge;

use halo2::halo2curves::{bn256::Fr, ff::PrimeField};
use num_rational::BigRational;
use secp256k1::ecdsa;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;

use super::native::SignedAttestation;

/// ECDSA public key
pub type ECDSAPublicKey = secp256k1::PublicKey;
/// ECDSA signature
pub type ECDSASignature = ecdsa::RecoverableSignature;

fn keccak256(data: &[u8]) -> Vec<u8> {
	let mut hasher = Keccak256::new();
	hasher.update(data);
	hasher.finalize().to_vec()
}

fn recover_ethereum_address_from_pk(public_key: ECDSAPublicKey) -> Fr {
	let public_key_bytes = public_key.serialize_uncompressed();
	let hashed_public_key = keccak256(&public_key_bytes[1..]);
	let address_bytes = &hashed_public_key[hashed_public_key.len() - 20..];

	let mut address_bytes_array = [0u8; 32];
	address_bytes_array[..address_bytes.len()].copy_from_slice(address_bytes);

	Fr::from_bytes(&address_bytes_array).unwrap()
}

/// Dynamic set for EigenTrust
pub struct EigenTrustAttestationSet<
	const NUM_NEIGHBOURS: usize,
	const NUM_ITERATIONS: usize,
	const INITIAL_SCORE: u128,
> {
	set: Vec<(Option<Fr>, Fr)>,
	ops: HashMap<ECDSAPublicKey, Vec<Fr>>,
}

impl<const NUM_NEIGHBOURS: usize, const NUM_ITERATIONS: usize, const INITIAL_SCORE: u128>
	EigenTrustAttestationSet<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>
{
	/// Constructs new instance
	pub fn new() -> Self {
		Self { set: vec![(None, Fr::zero()); NUM_NEIGHBOURS], ops: HashMap::new() }
	}

	/// Add new set member and initial score
	pub fn add_member(&mut self, pk: ECDSAPublicKey) {
		let pk_fr = recover_ethereum_address_from_pk(pk);

		let pos = self.set.iter().position(|&(x, _)| x == Some(pk_fr));
		// Make sure not already in the set
		assert!(pos.is_none());

		let first_available = self.set.iter().position(|&(x, _)| x.is_none());
		let index = first_available.unwrap();

		// Give the initial score.
		let initial_score = Fr::from_u128(INITIAL_SCORE);
		self.set[index] = (Some(pk_fr), initial_score);
	}

	/// Remove the member and its opinion
	pub fn remove_member(&mut self, pk: ECDSAPublicKey) {
		let pk_fr = recover_ethereum_address_from_pk(pk);
		let pos = self.set.iter().position(|&(x, _)| x == Some(pk_fr));
		// Make sure already in the set
		assert!(pos.is_some());

		let index = pos.unwrap();
		self.set[index] = (None, Fr::zero());

		self.ops.remove(&pk);
	}

	/// Update the opinion of the member
	pub fn update_op(&mut self, from: ECDSAPublicKey, op: Vec<Option<SignedAttestation>>) -> Fr {
		let from_pk = recover_ethereum_address_from_pk(from);
		let pos_from = self.set.iter().position(|&(x, _)| x == Some(from_pk));
		assert!(pos_from.is_some());

		let mut scores = vec![Fr::zero(); NUM_NEIGHBOURS];
		let mut hashes = Vec::new();
		for (i, att) in op.iter().enumerate() {
			let is_assigned_attestation = att.is_some();

			if is_assigned_attestation {
				let att = att.clone().unwrap();

				assert!(att.attestation.about == self.set[i].0.unwrap());

				let recovered = att.recover_public_key().unwrap();
				assert!(recovered == from);

				scores[i] = att.attestation.value;

				let hash = att.attestation.hash();
				hashes.push(hash);
			}
		}

		self.ops.insert(from, scores);

		let mut sponge_hasher = PoseidonNativeSponge::new();
		sponge_hasher.update(&hashes);
		let op_hash = sponge_hasher.squeeze();

		return op_hash;
	}

	fn filter_peers_ops(&self) {
		todo!()
	}

	/// Compute the EigenTrust score
	pub fn converge(&self) -> Vec<Fr> {
		todo!()
	}

	/// Compute the EigenTrust score using BigRational numbers
	pub fn converge_rational(&self) -> Vec<BigRational> {
		todo!()
	}
}

#[cfg(test)]
mod test {
	use rand::thread_rng;
	use secp256k1::{generate_keypair, Message, PublicKey, Secp256k1, SecretKey};

	use crate::dynamic_sets::native::AttestationFr;

	use super::*;

	const NUM_NEIGHBOURS: usize = 12;
	const NUM_ITERATIONS: usize = 10;
	const INITIAL_SCORE: u128 = 1000;

	fn sign_opinion<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
	>(
		sk: &SecretKey, pks: &[Option<PublicKey>], scores: &[Fr],
	) -> Vec<Option<SignedAttestation>> {
		assert!(pks.len() == NUM_NEIGHBOURS);
		assert!(scores.len() == NUM_NEIGHBOURS);

		let sign = Secp256k1::signing_only();

		let mut res = Vec::new();
		for i in 0..NUM_NEIGHBOURS {
			if pks[i].is_none() {
				res.push(None);
			} else {
				let about = recover_ethereum_address_from_pk(pks[i].clone().unwrap());
				let key = Fr::one();
				let value = scores[i].clone();
				let message = Fr::one();
				let attestation = AttestationFr::new(about, key, value, message);

				let message = attestation.hash().to_bytes();
				let signature = sign
					.sign_ecdsa_recoverable(&Message::from_slice(message.as_slice()).unwrap(), sk);

				let signed_attestation = SignedAttestation::new(attestation, signature);
				res.push(Some(signed_attestation));
			}
		}
		res
	}

	#[test]
	#[should_panic]
	fn test_add_member_in_initial_set() {
		let mut set =
			EigenTrustAttestationSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();
		let (_sk, pk) = generate_keypair(rng);

		set.add_member(pk);

		// Re-adding the member should panic
		set.add_member(pk);
	}

	#[test]
	#[should_panic]
	fn test_one_member_converge() {
		let mut set =
			EigenTrustAttestationSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();
		let (_sk, pk) = generate_keypair(rng);

		set.add_member(pk);

		set.converge();
	}

	#[test]
	#[should_panic]
	fn test_add_two_members_without_opinions() {
		let mut set =
			EigenTrustAttestationSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();
		let (_sk1, pk1) = generate_keypair(rng);
		let (_sk2, pk2) = generate_keypair(rng);

		set.add_member(pk1);
		set.add_member(pk2);

		set.converge();
	}

	#[ignore = "converge unimplemented"]
	#[test]
	fn test_add_two_members_with_one_opinion() {
		let mut set =
			EigenTrustAttestationSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();
		let (sk1, pk1) = generate_keypair(rng);
		let (_sk2, pk2) = generate_keypair(rng);

		set.add_member(pk1);
		set.add_member(pk2);

		// Peer1(pk1) signs the opinion
		let mut pks = [None; NUM_NEIGHBOURS];
		pks[0] = Some(pk1);
		pks[1] = Some(pk2);

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(INITIAL_SCORE);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk1, &pks, &scores);

		set.update_op(pk1, op1);

		set.converge();
	}

	#[ignore = "converge unimplemented"]
	#[test]
	fn test_add_two_members_with_opinions() {
		let mut set =
			EigenTrustAttestationSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();
		let (sk1, pk1) = generate_keypair(rng);
		let (sk2, pk2) = generate_keypair(rng);

		set.add_member(pk1);
		set.add_member(pk2);

		// Peer1(pk1) signs the opinion
		let mut pks = [None; NUM_NEIGHBOURS];
		pks[0] = Some(pk1);
		pks[1] = Some(pk2);

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(INITIAL_SCORE);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk1, &pks, &scores);

		set.update_op(pk1, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [None; NUM_NEIGHBOURS];
		pks[0] = Some(pk1);
		pks[1] = Some(pk2);

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(INITIAL_SCORE);

		let op2 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk2, &pks, &scores);

		set.update_op(pk2, op2);

		set.converge();
	}
}
