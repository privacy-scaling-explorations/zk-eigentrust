use crate::circuit::PoseidonNativeSponge;

use halo2::{
	arithmetic::Field,
	halo2curves::{bn256::Fr, ff::PrimeField},
};
use num_rational::BigRational;
use secp256k1::{constants::ONE, ecdsa, Message, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;

use super::native::{AttestationFr, SignedAttestation};

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

impl Default for AttestationFr {
	fn default() -> Self {
		AttestationFr {
			about: Fr::default(),
			key: Fr::default(),
			value: Fr::default(),
			message: Fr::default(),
		}
	}
}

impl Default for SignedAttestation {
	fn default() -> Self {
		let attestation = AttestationFr::default();

		let s = Secp256k1::signing_only();
		let msg = attestation.hash().to_bytes();
		let sk = SecretKey::from_slice(&ONE).unwrap();
		let signature =
			s.sign_ecdsa_recoverable(&Message::from_slice(msg.as_slice()).unwrap(), &sk);

		Self { attestation, signature }
	}
}

/// Dynamic set for EigenTrust
pub struct EigenTrustAttestationSet<
	const NUM_NEIGHBOURS: usize,
	const NUM_ITERATIONS: usize,
	const INITIAL_SCORE: u128,
> {
	set: Vec<(Fr, Fr)>,
	ops: HashMap<Fr, Vec<Fr>>,
}

impl<const NUM_NEIGHBOURS: usize, const NUM_ITERATIONS: usize, const INITIAL_SCORE: u128>
	EigenTrustAttestationSet<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>
{
	/// Constructs new instance
	pub fn new() -> Self {
		Self { set: vec![(Fr::zero(), Fr::zero()); NUM_NEIGHBOURS], ops: HashMap::new() }
	}

	/// Add new set member and initial score
	pub fn add_member(&mut self, pk: ECDSAPublicKey) {
		let pk_fr = recover_ethereum_address_from_pk(pk);

		let pos = self.set.iter().position(|&(x, _)| x == pk_fr);
		// Make sure not already in the set
		assert!(pos.is_none());

		let first_available = self.set.iter().position(|&(x, _)| x == Fr::zero());
		let index = first_available.unwrap();

		// Give the initial score.
		let initial_score = Fr::from_u128(INITIAL_SCORE);
		self.set[index] = (pk_fr, initial_score);
	}

	/// Remove the member and its opinion
	pub fn remove_member(&mut self, pk: ECDSAPublicKey) {
		let pk_fr = recover_ethereum_address_from_pk(pk);
		let pos = self.set.iter().position(|&(x, _)| x == pk_fr);
		// Make sure already in the set
		assert!(pos.is_some());

		let index = pos.unwrap();
		self.set[index] = (Fr::zero(), Fr::zero());

		self.ops.remove(&pk_fr);
	}

	/// Update the opinion of the member
	pub fn update_op(&mut self, from: ECDSAPublicKey, op: Vec<SignedAttestation>) -> Fr {
		let from_pk = recover_ethereum_address_from_pk(from);
		let pos_from = self.set.iter().position(|&(x, _)| x == from_pk);
		assert!(pos_from.is_some());

		let mut scores = vec![Fr::zero(); NUM_NEIGHBOURS];
		let mut hashes = Vec::new();
		for (i, att) in op.iter().enumerate() {
			let is_default_pubkey = self.set[i].0 == Fr::zero();

			if is_default_pubkey {
				scores[i] = Fr::default();
				hashes.push(AttestationFr::default().hash());
			} else {
				assert!(att.attestation.about == self.set[i].0);

				let recovered = att.recover_public_key().unwrap();
				assert!(recovered == from);

				scores[i] = att.attestation.value;

				let hash = att.attestation.hash();
				hashes.push(hash);
			}
		}

		self.ops.insert(from_pk, scores);

		let mut sponge_hasher = PoseidonNativeSponge::new();
		sponge_hasher.update(&hashes);
		let op_hash = sponge_hasher.squeeze();

		return op_hash;
	}

	fn filter_peers_ops(&self) -> HashMap<Fr, Vec<Fr>> {
		let mut filtered_ops: HashMap<Fr, Vec<Fr>> = HashMap::new();

		// Distribute the scores to valid peers
		for i in 0..NUM_NEIGHBOURS {
			let (pk_i, _) = self.set[i].clone();
			if pk_i == Fr::zero() {
				continue;
			}

			let default_ops = vec![Fr::default(); NUM_NEIGHBOURS];
			let mut ops_i = self.ops.get(&pk_i).unwrap_or(&default_ops).clone();

			// Update the opinion array - pairs of (key, score)
			for j in 0..NUM_NEIGHBOURS {
				// Conditions fro nullifying the score
				// 1. pk_j == 0(null or default key)
				// 2. i == j
				let is_pk_j_null = self.set[j].0 == Fr::zero();
				let is_pk_i = i == j;
				if is_pk_j_null || is_pk_i {
					ops_i[j] = Fr::zero();
				}
			}

			// Distribute the scores
			let op_score_sum = ops_i.iter().fold(Fr::zero(), |acc, &score| acc + score);
			if op_score_sum == Fr::zero() {
				for j in 0..NUM_NEIGHBOURS {
					let is_diff_pk = i != j;
					let is_not_null = self.set[j].0 != Fr::zero();

					// Conditions for distributing the score
					// 1. i != j
					// 2. pk_i != Fr::default()
					if is_diff_pk && is_not_null {
						ops_i[j] = Fr::from(1);
					}
				}
			}
			filtered_ops.insert(pk_i, ops_i);
		}
		println!("filtered_ops: {:?}", filtered_ops);

		filtered_ops
	}

	/// Compute the EigenTrust score
	pub fn converge(&self) -> Vec<Fr> {
		// There should be at least 2 valid peers(valid opinions) for calculation
		let valid_peers = self.set.iter().filter(|(pk, _)| *pk != Fr::zero()).count();
		assert!(valid_peers >= 2, "Insufficient peers for calculation!");

		let filtered_ops: HashMap<Fr, Vec<Fr>> = self.filter_peers_ops();

		let mut ops = Vec::new();
		for i in 0..NUM_NEIGHBOURS {
			let (pk, _) = self.set[i];
			if pk == Fr::zero() {
				ops.push(vec![Fr::zero(); NUM_NEIGHBOURS]);
			} else {
				let scores = filtered_ops.get(&pk).unwrap();
				ops.push(scores.clone());
			}
		}

		let mut ops_norm = vec![vec![Fr::zero(); NUM_NEIGHBOURS]; NUM_NEIGHBOURS];
		// Normalize the opinion scores
		for i in 0..NUM_NEIGHBOURS {
			let op_score_sum: Fr = ops[i].iter().sum();
			let inverted_sum = op_score_sum.invert().unwrap_or(Fr::zero());

			for j in 0..NUM_NEIGHBOURS {
				let ops_ij = ops[i][j];
				ops_norm[i][j] = ops_ij * inverted_sum;
			}
		}

		// By this point we should use filtered opinions
		let mut s: Vec<Fr> = self.set.iter().map(|(_, score)| score.clone()).collect();
		let mut new_s: Vec<Fr> = self.set.iter().map(|(_, score)| score.clone()).collect();
		for _ in 0..NUM_ITERATIONS {
			for i in 0..NUM_NEIGHBOURS {
				let mut score_i_sum = Fr::zero();
				for j in 0..NUM_NEIGHBOURS {
					let score = ops_norm[j][i].clone() * s[j].clone();
					score_i_sum = score + score_i_sum;
				}
				new_s[i] = score_i_sum;
			}
			s = new_s.clone();
		}

		// Assert the score sum for checking the possible reputation leak
		let sum_initial = self.set.iter().fold(Fr::zero(), |acc, &(_, score)| acc + score);
		let sum_final = s.iter().fold(Fr::zero(), |acc, &score| acc + score);
		assert!(sum_initial == sum_final);

		s
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
	) -> Vec<SignedAttestation> {
		assert!(pks.len() == NUM_NEIGHBOURS);
		assert!(scores.len() == NUM_NEIGHBOURS);

		let sign = Secp256k1::signing_only();

		let mut res = Vec::new();
		for i in 0..NUM_NEIGHBOURS {
			if pks[i].is_none() {
				res.push(SignedAttestation::default())
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
				res.push(signed_attestation);
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

	#[test]
	fn test_three_members_with_opinions() {
		let mut set =
			EigenTrustAttestationSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();
		let (sk1, pk1) = generate_keypair(rng);
		let (sk2, pk2) = generate_keypair(rng);
		let (sk3, pk3) = generate_keypair(rng);

		set.add_member(pk1);
		set.add_member(pk2);
		set.add_member(pk3);

		// Peer1(pk1) signs the opinion
		let mut pks = [None; NUM_NEIGHBOURS];
		pks[0] = Some(pk1);
		pks[1] = Some(pk2);
		pks[2] = Some(pk3);

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(300);
		scores[2] = Fr::from_u128(700);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk1, &pks, &scores);

		set.update_op(pk1, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [None; NUM_NEIGHBOURS];
		pks[0] = Some(pk1);
		pks[1] = Some(pk2);
		pks[2] = Some(pk3);

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[2] = Fr::from_u128(400);

		let op2 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk2, &pks, &scores);

		set.update_op(pk2, op2);

		// Peer3(pk3) signs the opinion
		let mut pks = [None; NUM_NEIGHBOURS];
		pks[0] = Some(pk1);
		pks[1] = Some(pk2);
		pks[2] = Some(pk3);

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[1] = Fr::from_u128(400);

		let op3 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk3, &pks, &scores);

		set.update_op(pk3, op3);

		set.converge();
	}

	#[test]
	fn test_add_three_members_with_two_opinions() {
		let mut set =
			EigenTrustAttestationSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();
		let (sk1, pk1) = generate_keypair(rng);
		let (sk2, pk2) = generate_keypair(rng);
		let (sk3, pk3) = generate_keypair(rng);

		set.add_member(pk1);
		set.add_member(pk2);
		set.add_member(pk3);

		// Peer1(pk1) signs the opinion
		let mut pks = [None; NUM_NEIGHBOURS];
		pks[0] = Some(pk1);
		pks[1] = Some(pk2);
		pks[2] = Some(pk3);

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(300);
		scores[2] = Fr::from_u128(700);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk1, &pks, &scores);

		set.update_op(pk1, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [None; NUM_NEIGHBOURS];
		pks[0] = Some(pk1);
		pks[1] = Some(pk2);
		pks[2] = Some(pk3);

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[2] = Fr::from_u128(400);

		let op2 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk2, &pks, &scores);

		set.update_op(pk2, op2);

		set.converge();
	}

	#[test]
	fn test_add_3_members_with_3_ops_quit_1_member() {
		let mut set =
			EigenTrustAttestationSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();
		let (sk1, pk1) = generate_keypair(rng);
		let (sk2, pk2) = generate_keypair(rng);
		let (sk3, pk3) = generate_keypair(rng);

		set.add_member(pk1);
		set.add_member(pk2);
		set.add_member(pk3);

		// Peer1(pk1) signs the opinion
		let mut pks = [None; NUM_NEIGHBOURS];
		pks[0] = Some(pk1);
		pks[1] = Some(pk2);
		pks[2] = Some(pk3);

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(300);
		scores[2] = Fr::from_u128(700);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk1, &pks, &scores);

		set.update_op(pk1, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [None; NUM_NEIGHBOURS];
		pks[0] = Some(pk1);
		pks[1] = Some(pk2);
		pks[2] = Some(pk3);

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[2] = Fr::from_u128(400);

		let op2 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk2, &pks, &scores);

		set.update_op(pk2, op2);

		// Peer3(pk3) signs the opinion
		let mut pks = [None; NUM_NEIGHBOURS];
		pks[0] = Some(pk1);
		pks[1] = Some(pk2);
		pks[2] = Some(pk3);

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[1] = Fr::from_u128(400);

		let op3 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&sk3, &pks, &scores);

		set.update_op(pk3, op3);

		set.converge();

		// Peer2 quits
		set.remove_member(pk2);

		set.converge();
	}
}
