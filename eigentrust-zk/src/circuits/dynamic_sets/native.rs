use crate::{
	circuits::{opinion::native::Opinion, RationalScore, HASHER_WIDTH},
	ecdsa::native::{PublicKey, Signature},
	params::{ecc::EccParams, rns::RnsParams},
	utils::fe_to_big,
	FieldExt, Hasher, SpongeHasher,
};
use halo2::halo2curves::CurveAffine;
use itertools::Itertools;
use num_bigint::{BigInt, ToBigInt};
use num_rational::BigRational;
use num_traits::{FromPrimitive, One, Zero};
use std::{collections::HashMap, marker::PhantomData};

/// Attestation submission struct
#[derive(Clone, Debug)]
pub struct SignedAttestation<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::ScalarExt: FieldExt,
{
	/// Attestation
	pub attestation: Attestation<N>,
	/// Signature
	pub signature: Signature<C, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	SignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::ScalarExt: FieldExt,
{
	/// Constructs a new instance
	pub fn new(
		attestation: Attestation<N>, signature: Signature<C, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { attestation, signature }
	}
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Default
	for SignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::ScalarExt: FieldExt,
{
	fn default() -> Self {
		let attestation = Attestation::default();
		let signature = Signature::default();

		Self { attestation, signature }
	}
}

/// Attestation struct
#[derive(Clone, Default, Debug, PartialEq, PartialOrd)]
pub struct Attestation<F: FieldExt> {
	/// Ethereum address of peer being rated
	pub about: F,
	/// Unique identifier for the action being rated
	pub domain: F,
	/// Given rating for the action
	pub value: F,
	/// Optional field for attaching additional information to the attestation
	pub message: F,
}

impl<F: FieldExt> Attestation<F> {
	/// Construct a new attestation struct
	pub fn new(about: F, domain: F, value: F, message: F) -> Self {
		Self { about, domain, value, message }
	}

	/// Hash attestation
	pub fn hash<const W: usize, H: Hasher<F, W>>(&self) -> F {
		let mut input: [F; W] = [F::ZERO; W];
		input[0] = self.about;
		input[1] = self.domain;
		input[2] = self.value;
		input[3] = self.message;
		H::new(input).finalize()[0]
	}
}

/// Dynamic set for EigenTrust
#[derive(Default)]
pub struct EigenTrustSet<
	const NUM_NEIGHBOURS: usize,
	const NUM_ITERATIONS: usize,
	const INITIAL_SCORE: u128,
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
	EC,
	H: Hasher<N, HASHER_WIDTH>,
	SH: SpongeHasher<N>,
> where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::ScalarExt: FieldExt,
	C::Base: FieldExt,
{
	set: Vec<(N, N)>,
	ops: HashMap<N, Vec<N>>,
	domain: N,
	_p: PhantomData<(C, P, EC, H, SH)>,
}

impl<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
		C: CurveAffine,
		N: FieldExt,
		const NUM_LIMBS: usize,
		const NUM_BITS: usize,
		P,
		EC,
		H: Hasher<N, HASHER_WIDTH>,
		SH: SpongeHasher<N>,
	>
	EigenTrustSet<
		NUM_NEIGHBOURS,
		NUM_ITERATIONS,
		INITIAL_SCORE,
		C,
		N,
		NUM_LIMBS,
		NUM_BITS,
		P,
		EC,
		H,
		SH,
	> where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::ScalarExt: FieldExt,
	C::Base: FieldExt,
{
	/// Constructs new instance
	pub fn new(domain: N) -> Self {
		Self {
			set: vec![(N::ZERO, N::ZERO); NUM_NEIGHBOURS],
			ops: HashMap::new(),
			domain,
			_p: PhantomData,
		}
	}

	/// Add new set member and initial score
	pub fn add_member(&mut self, pk: N) {
		let pos = self.set.iter().position(|&(x, _)| x == pk);
		// Make sure not already in the set
		assert!(pos.is_none());

		let first_available = self.set.iter().position(|&(x, _)| x == N::ZERO);
		let index = first_available.unwrap();

		// Give the initial score.
		let initial_score = N::from_u128(INITIAL_SCORE);
		self.set[index] = (pk, initial_score);
	}

	/// Remove the member and its opinion
	pub fn remove_member(&mut self, pk: N) {
		let pos = self.set.iter().position(|&(x, _)| x == pk);
		// Make sure already in the set
		assert!(pos.is_some());

		let index = pos.unwrap();
		self.set[index] = (N::ZERO, N::ZERO);

		self.ops.remove(&pk);
	}

	/// Update the opinion of the member
	pub fn update_op(
		&mut self, from: PublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
		op: Vec<Option<SignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>>>,
	) -> N {
		let default_att = SignedAttestation::default();
		let op_unwrapped =
			op.iter().map(|x| x.clone().unwrap_or(default_att.clone())).collect_vec();
		let op = Opinion::<NUM_NEIGHBOURS, C, N, NUM_LIMBS, NUM_BITS, P, EC, H, SH>::new(
			from, op_unwrapped, self.domain,
		);
		let set = self.set.iter().map(|&(pk, _)| pk).collect();
		let (from_pk, scores, op_hash) = op.validate(set);

		self.ops.insert(from_pk, scores);

		op_hash
	}

	/// Method for filtering invalid opinions
	fn filter_peers_ops(&self) -> HashMap<N, Vec<N>> {
		let mut filtered_ops: HashMap<N, Vec<N>> = HashMap::new();

		// Distribute the scores to valid peers
		for i in 0..NUM_NEIGHBOURS {
			let (pk_i, _) = self.set[i];
			if pk_i == N::ZERO {
				continue;
			}

			let default_ops = vec![N::default(); NUM_NEIGHBOURS];
			let mut ops_i = self.ops.get(&pk_i).unwrap_or(&default_ops).clone();

			// Update the opinion array - pairs of (key, score)
			for j in 0..NUM_NEIGHBOURS {
				let (pk_j, _) = self.set[j];

				// Conditions fro nullifying the score
				// 1. pk_j == 0 (Default key)
				// 2. pk_j == pk_i
				let is_pk_j_default = pk_j == N::ZERO;
				let is_pk_i = pk_j == pk_i;

				if is_pk_j_default || is_pk_i {
					ops_i[j] = N::ZERO;
				}
			}

			// Distribute the scores
			let op_score_sum = ops_i.iter().fold(N::ZERO, |acc, &score| acc + score);
			if op_score_sum == N::ZERO {
				for j in 0..NUM_NEIGHBOURS {
					let (pk_j, _) = self.set[j];

					// Conditions for distributing the score
					// 1. pk_j != pk_i
					// 2. pk_j != 0 (Default key)
					let is_diff_pk = pk_j != pk_i;
					let is_not_default = pk_j != N::ZERO;

					if is_diff_pk && is_not_default {
						ops_i[j] = N::from(1);
					}
				}
			}
			filtered_ops.insert(pk_i, ops_i);
		}

		filtered_ops
	}

	/// Compute the EigenTrust score
	pub fn converge(&self) -> Vec<N> {
		// There should be at least 2 valid peers(valid opinions) for calculation
		let valid_peers = self.set.iter().filter(|(pk, _)| *pk != N::ZERO).count();
		assert!(valid_peers >= 2, "Insufficient peers for calculation!");

		// Prepare the opinion scores
		let mut ops = Vec::new();
		let filtered_ops: HashMap<N, Vec<N>> = self.filter_peers_ops();
		for i in 0..NUM_NEIGHBOURS {
			let (pk, _) = self.set[i];
			if pk == N::ZERO {
				ops.push(vec![N::ZERO; NUM_NEIGHBOURS]);
			} else {
				let scores = filtered_ops.get(&pk).unwrap();
				ops.push(scores.clone());
			}
		}

		// Normalize the opinion scores
		let mut ops_norm = vec![vec![N::ZERO; NUM_NEIGHBOURS]; NUM_NEIGHBOURS];
		for i in 0..NUM_NEIGHBOURS {
			let op_score_sum: N = ops[i].iter().sum();
			let inverted_sum = op_score_sum.invert().unwrap_or(N::ZERO);

			for j in 0..NUM_NEIGHBOURS {
				let ops_ij = ops[i][j];
				ops_norm[i][j] = ops_ij * inverted_sum;
			}
		}

		// Compute the EigenTrust scores using the filtered and normalized scores
		let mut s: Vec<N> = self.set.iter().map(|(_, score)| *score).collect();
		let mut new_s: Vec<N> = self.set.iter().map(|(_, score)| *score).collect();
		for _ in 0..NUM_ITERATIONS {
			for i in 0..NUM_NEIGHBOURS {
				let mut score_i_sum = N::ZERO;
				for j in 0..NUM_NEIGHBOURS {
					let score = ops_norm[j][i] * s[j];
					score_i_sum = score + score_i_sum;
				}
				new_s[i] = score_i_sum;
			}
			s = new_s.clone();
		}

		// Assert the score sum for checking the possible reputation leak
		let sum_initial = self.set.iter().fold(N::ZERO, |acc, &(_, score)| acc + score);
		let sum_final = s.iter().fold(N::ZERO, |acc, &score| acc + score);
		assert!(sum_initial == sum_final);

		s
	}

	/// Compute the EigenTrust score using BigRational numbers
	pub fn converge_rational(&self) -> Vec<RationalScore> {
		let mut filtered_ops: HashMap<N, Vec<N>> = self.filter_peers_ops();

		let mut ops = Vec::new();
		for i in 0..NUM_NEIGHBOURS {
			let (pk, _) = self.set[i];
			if pk == N::ZERO {
				ops.push(vec![BigInt::zero(); NUM_NEIGHBOURS]);
			} else {
				let ops_i = filtered_ops.get_mut(&pk).unwrap();
				let scores =
					ops_i.iter().map(|&score| fe_to_big(score).to_bigint().unwrap()).collect();
				ops.push(scores);
			}
		}

		// Sanity check
		assert!(ops.len() == NUM_NEIGHBOURS);
		for op in &ops {
			assert!(op.len() == NUM_NEIGHBOURS);
		}

		let init_score_bn = BigInt::from_u128(INITIAL_SCORE).unwrap();
		let mut s: Vec<BigRational> =
			vec![BigRational::from_integer(init_score_bn); NUM_NEIGHBOURS];

		let mut ops_norm = vec![vec![BigRational::zero(); NUM_NEIGHBOURS]; NUM_NEIGHBOURS];
		for i in 0..NUM_NEIGHBOURS {
			let mut op_score_sum = ops[i].iter().fold(BigInt::zero(), |acc, score| acc + score);
			if op_score_sum.is_zero() {
				op_score_sum = BigInt::one();
			}

			for j in 0..NUM_NEIGHBOURS {
				let score = ops[i][j].clone();
				ops_norm[i][j] = BigRational::new(score, op_score_sum.clone());
			}
		}

		let mut new_s = s.clone();
		for _ in 0..NUM_ITERATIONS {
			for i in 0..NUM_NEIGHBOURS {
				let mut score_i_sum = BigRational::zero();
				for j in 0..NUM_NEIGHBOURS {
					let score = ops_norm[j][i].clone() * s[j].clone();
					score_i_sum = score + score_i_sum;
				}
				new_s[i] = score_i_sum;
			}
			s = new_s.clone();
		}
		s
	}
}

#[cfg(test)]
mod test {
	use crate::{
		circuits::{PoseidonNativeHasher, PoseidonNativeSponge},
		ecdsa::native::EcdsaKeypair,
		params::{ecc::secp256k1::Secp256k1Params, rns::secp256k1::Secp256k1_4_68},
		utils::big_to_fe,
	};

	use super::*;
	use halo2::halo2curves::{bn256::Fr, ff::PrimeField, secp256k1::Secp256k1Affine};
	use num_rational::BigRational;
	use rand::thread_rng;
	use std::time::Instant;

	const DOMAIN: u128 = 42;
	const NUM_NEIGHBOURS: usize = 12;
	const NUM_ITERATIONS: usize = 10;
	const INITIAL_SCORE: u128 = 1000;

	type C = Secp256k1Affine;
	type N = Fr;
	const NUM_LIMBS: usize = 4;
	const NUM_BITS: usize = 68;
	type P = Secp256k1_4_68;
	type EC = Secp256k1Params;
	type H = PoseidonNativeHasher;
	type SH = PoseidonNativeSponge;

	fn sign_opinion<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
	>(
		keypair: &EcdsaKeypair<C, N, NUM_LIMBS, NUM_BITS, P, EC>, pks: &[N], scores: &[N],
	) -> Vec<Option<SignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>>> {
		assert!(pks.len() == NUM_NEIGHBOURS);
		assert!(scores.len() == NUM_NEIGHBOURS);
		let rng = &mut thread_rng();

		let mut res = Vec::new();
		for i in 0..NUM_NEIGHBOURS {
			if pks[i] == N::zero() {
				res.push(None)
			} else {
				let (about, key, value, message) =
					(pks[i], N::from_u128(DOMAIN), scores[i], N::zero());
				let attestation = Attestation::new(about, key, value, message);
				let msg = big_to_fe(fe_to_big(
					attestation.hash::<HASHER_WIDTH, PoseidonNativeHasher>(),
				));
				let signature = keypair.sign(msg, rng);
				let signed_attestation = SignedAttestation::new(attestation, signature);

				res.push(Some(signed_attestation));
			}
		}
		res
	}

	#[test]
	#[should_panic]
	fn test_add_member_in_initial_set() {
		let domain = N::from_u128(DOMAIN);
		let mut set = EigenTrustSet::<
			NUM_NEIGHBOURS,
			NUM_ITERATIONS,
			INITIAL_SCORE,
			C,
			N,
			NUM_LIMBS,
			NUM_BITS,
			P,
			EC,
			H,
			SH,
		>::new(domain);

		let rng = &mut thread_rng();

		let keypair = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);
		let pk = keypair.public_key.to_address();

		set.add_member(pk);

		// Re-adding the member should panic
		set.add_member(pk);
	}

	#[test]
	#[should_panic]
	fn test_one_member_converge() {
		let domain = N::from_u128(DOMAIN);
		let mut set = EigenTrustSet::<
			NUM_NEIGHBOURS,
			NUM_ITERATIONS,
			INITIAL_SCORE,
			C,
			N,
			NUM_LIMBS,
			NUM_BITS,
			P,
			EC,
			H,
			SH,
		>::new(domain);

		let rng = &mut thread_rng();

		let keypair = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);
		let pk_fr = keypair.public_key.to_address();

		set.add_member(pk_fr);

		set.converge();
	}

	#[test]
	fn test_add_two_members_without_opinions() {
		let domain = N::from_u128(DOMAIN);
		let mut set = EigenTrustSet::<
			NUM_NEIGHBOURS,
			NUM_ITERATIONS,
			INITIAL_SCORE,
			C,
			N,
			NUM_LIMBS,
			NUM_BITS,
			P,
			EC,
			H,
			SH,
		>::new(domain);

		let rng = &mut thread_rng();

		let keypair1 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);
		let keypair2 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);

		let pk1 = keypair1.public_key.to_address();
		let pk2 = keypair2.public_key.to_address();

		set.add_member(pk1);
		set.add_member(pk2);

		set.converge();
	}

	#[test]
	fn test_add_two_members_with_one_opinion() {
		let domain = N::from_u128(DOMAIN);
		let mut set = EigenTrustSet::<
			NUM_NEIGHBOURS,
			NUM_ITERATIONS,
			INITIAL_SCORE,
			C,
			N,
			NUM_LIMBS,
			NUM_BITS,
			P,
			EC,
			H,
			SH,
		>::new(domain);

		let rng = &mut thread_rng();

		let keypair1 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);
		let keypair2 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);

		let pk1_fr = keypair1.public_key.to_address();
		let pk2_fr = keypair2.public_key.to_address();

		set.add_member(pk1_fr);
		set.add_member(pk2_fr);

		// Peer1(pk1) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(INITIAL_SCORE);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&keypair1, &pks, &scores);

		set.update_op(keypair1.public_key, op1);

		set.converge();
	}

	#[test]
	fn test_add_two_members_with_opinions() {
		let domain = N::from_u128(DOMAIN);
		let mut set = EigenTrustSet::<
			NUM_NEIGHBOURS,
			NUM_ITERATIONS,
			INITIAL_SCORE,
			C,
			N,
			NUM_LIMBS,
			NUM_BITS,
			P,
			EC,
			H,
			SH,
		>::new(domain);

		let rng = &mut thread_rng();

		let keypair1 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);
		let keypair2 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);

		let pk1_fr = keypair1.public_key.to_address();
		let pk2_fr = keypair2.public_key.to_address();

		set.add_member(pk1_fr);
		set.add_member(pk2_fr);

		// Peer1(pk1) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(INITIAL_SCORE);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&keypair1, &pks, &scores);

		set.update_op(keypair1.public_key, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(INITIAL_SCORE);

		let op2 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&keypair2, &pks, &scores);

		set.update_op(keypair2.public_key, op2);

		set.converge();
	}

	#[test]
	fn test_add_three_members_with_opinions() {
		let domain = N::from_u128(DOMAIN);
		let mut set = EigenTrustSet::<
			NUM_NEIGHBOURS,
			NUM_ITERATIONS,
			INITIAL_SCORE,
			C,
			N,
			NUM_LIMBS,
			NUM_BITS,
			P,
			EC,
			H,
			SH,
		>::new(domain);

		let rng = &mut thread_rng();
		let keypair1 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);
		let keypair2 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);
		let keypair3 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);

		let pk1_fr = keypair1.public_key.to_address();
		let pk2_fr = keypair2.public_key.to_address();
		let pk3_fr = keypair3.public_key.to_address();

		set.add_member(pk1_fr);
		set.add_member(pk2_fr);
		set.add_member(pk3_fr);

		// Peer1(pk1) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(300);
		scores[2] = Fr::from_u128(700);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&keypair1, &pks, &scores);

		set.update_op(keypair1.public_key, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[2] = Fr::from_u128(400);

		let op2 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&keypair2, &pks, &scores);

		set.update_op(keypair2.public_key, op2);

		// Peer3(pk3) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[1] = Fr::from_u128(400);

		let op3 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&keypair3, &pks, &scores);

		set.update_op(keypair3.public_key, op3);

		set.converge();
	}

	#[test]
	fn test_add_three_members_with_two_opinions() {
		let domain = N::from_u128(DOMAIN);
		let mut set = EigenTrustSet::<
			NUM_NEIGHBOURS,
			NUM_ITERATIONS,
			INITIAL_SCORE,
			C,
			N,
			NUM_LIMBS,
			NUM_BITS,
			P,
			EC,
			H,
			SH,
		>::new(domain);

		let rng = &mut thread_rng();

		let keypair1 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);
		let keypair2 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);
		let keypair3 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);

		let pk1_fr = keypair1.public_key.to_address();
		let pk2_fr = keypair2.public_key.to_address();
		let pk3_fr = keypair3.public_key.to_address();

		set.add_member(pk1_fr);
		set.add_member(pk2_fr);
		set.add_member(pk3_fr);

		// Peer1(pk1) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(300);
		scores[2] = Fr::from_u128(700);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&keypair1, &pks, &scores);

		set.update_op(keypair1.public_key, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[2] = Fr::from_u128(400);

		let op2 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&keypair2, &pks, &scores);

		set.update_op(keypair2.public_key, op2);

		set.converge();
	}

	#[test]
	fn test_add_3_members_with_3_ops_quit_1_member() {
		let domain = N::from_u128(DOMAIN);
		let mut set = EigenTrustSet::<
			NUM_NEIGHBOURS,
			NUM_ITERATIONS,
			INITIAL_SCORE,
			C,
			N,
			NUM_LIMBS,
			NUM_BITS,
			P,
			EC,
			H,
			SH,
		>::new(domain);

		let rng = &mut thread_rng();

		let keypair1 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);
		let keypair2 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);
		let keypair3 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);

		let pk1_fr = keypair1.public_key.to_address();
		let pk2_fr = keypair2.public_key.to_address();
		let pk3_fr = keypair3.public_key.to_address();

		set.add_member(pk1_fr);
		set.add_member(pk2_fr);
		set.add_member(pk3_fr);

		// Peer1(pk1) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(300);
		scores[2] = Fr::from_u128(700);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&keypair1, &pks, &scores);

		set.update_op(keypair1.public_key, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[2] = Fr::from_u128(400);

		let op2 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&keypair2, &pks, &scores);

		set.update_op(keypair2.public_key, op2);

		// Peer3(pk3) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[1] = Fr::from_u128(400);

		let op3 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&keypair3, &pks, &scores);

		set.update_op(keypair3.public_key, op3);

		set.converge();

		// Peer2 quits
		set.remove_member(pk2_fr);

		set.converge();
	}

	#[test]
	fn test_add_3_members_with_2_ops_quit_1_member_1_op() {
		let domain = N::from_u128(DOMAIN);
		let mut set = EigenTrustSet::<
			NUM_NEIGHBOURS,
			NUM_ITERATIONS,
			INITIAL_SCORE,
			C,
			N,
			NUM_LIMBS,
			NUM_BITS,
			P,
			EC,
			H,
			SH,
		>::new(domain);

		let rng = &mut thread_rng();

		let keypair1 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);
		let keypair2 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);
		let keypair3 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);

		let pk1_fr = keypair1.public_key.to_address();
		let pk2_fr = keypair2.public_key.to_address();
		let pk3_fr = keypair3.public_key.to_address();

		set.add_member(pk1_fr);
		set.add_member(pk2_fr);
		set.add_member(pk3_fr);

		// Peer1(pk1) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[1] = Fr::from_u128(300);
		scores[2] = Fr::from_u128(700);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&keypair1, &pks, &scores);

		set.update_op(keypair1.public_key, op1);

		// Peer2(pk2) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(600);
		scores[2] = Fr::from_u128(400);

		let op2 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&keypair2, &pks, &scores);

		set.update_op(keypair2.public_key, op2);

		set.converge();

		// // Peer1 quits
		// set.remove_member(pk1);

		// set.converge();
	}

	#[test]
	fn test_filter_peers_ops() {
		//	Filter the peers with following opinions:
		//			1	2	3	4	 5
		//		-----------------------
		//		1	10	10	.	.	10
		//		2	.	.	30	.	.
		//		3	10	.	.	.	.
		//		4	.	.	.	.	.
		//		5	.	.	.	.	.

		let rng = &mut thread_rng();

		let keypair1 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);
		let keypair2 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);
		let keypair3 = EcdsaKeypair::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::generate_keypair(rng);

		let pk1_fr = keypair1.public_key.to_address();
		let pk2_fr = keypair2.public_key.to_address();
		let pk3_fr = keypair3.public_key.to_address();

		// Peer1(pk1) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(10);
		scores[1] = Fr::from_u128(10);

		let op1 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&keypair1, &pks, &scores);

		// Peer2(pk2) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[2] = Fr::from_u128(30);

		let op2 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&keypair2, &pks, &scores);

		// Peer3(pk3) signs the opinion
		let mut pks = [Fr::zero(); NUM_NEIGHBOURS];
		pks[0] = pk1_fr;
		pks[1] = pk2_fr;
		pks[2] = pk3_fr;

		let mut scores = [Fr::zero(); NUM_NEIGHBOURS];
		scores[0] = Fr::from_u128(10);

		let op3 =
			sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&keypair3, &pks, &scores);

		let domain = N::from_u128(DOMAIN);
		// Setup EigenTrustSet
		let mut eigen_trust_set = EigenTrustSet::<
			NUM_NEIGHBOURS,
			NUM_ITERATIONS,
			INITIAL_SCORE,
			C,
			N,
			NUM_LIMBS,
			NUM_BITS,
			P,
			EC,
			H,
			SH,
		>::new(domain);

		eigen_trust_set.add_member(pk1_fr);
		eigen_trust_set.add_member(pk2_fr);
		eigen_trust_set.add_member(pk3_fr);

		eigen_trust_set.update_op(keypair1.public_key, op1);
		eigen_trust_set.update_op(keypair2.public_key, op2);
		eigen_trust_set.update_op(keypair3.public_key, op3);

		let filtered_ops = eigen_trust_set.filter_peers_ops();

		let final_peers_count =
			eigen_trust_set.set.iter().filter(|&&(pk, _)| pk != Fr::zero()).count();
		let final_ops_count = filtered_ops.keys().count();
		assert!(final_peers_count == final_ops_count);
	}

	fn eigen_trust_set_testing_helper<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
	>(
		ops: Vec<Vec<Fr>>,
	) -> (Vec<Fr>, Vec<BigRational>) {
		assert!(ops.len() == NUM_NEIGHBOURS);
		for op in &ops {
			assert!(op.len() == NUM_NEIGHBOURS);
		}

		let domain = N::from_u128(DOMAIN);
		let mut set = EigenTrustSet::<
			NUM_NEIGHBOURS,
			NUM_ITERATIONS,
			INITIAL_SCORE,
			C,
			N,
			NUM_LIMBS,
			NUM_BITS,
			P,
			EC,
			H,
			SH,
		>::new(domain);

		let rng = &mut thread_rng();

		let keys: Vec<
			EcdsaKeypair<Secp256k1Affine, Fr, NUM_LIMBS, NUM_BITS, Secp256k1_4_68, Secp256k1Params>,
		> = (0..NUM_NEIGHBOURS).into_iter().map(|_| EcdsaKeypair::generate_keypair(rng)).collect();

		let pks_fr: Vec<Fr> = keys.iter().map(|key| key.public_key.to_address()).collect();

		// Add the publicKey to the set
		pks_fr.iter().for_each(|f| set.add_member(f.clone()));

		// Update the opinions
		for i in 0..NUM_NEIGHBOURS {
			let scores = ops[i].to_vec();

			let op_i = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
				&keys[i], &pks_fr, &scores,
			);

			let pk_i = keys[i].public_key.clone();
			set.update_op(pk_i, op_i);
		}

		let s = set.converge();
		let s_ratios = set.converge_rational();

		(s, s_ratios)
	}

	#[test]
	fn test_scaling_1() {
		const NUM_NEIGHBOURS: usize = 10;
		const NUM_ITERATIONS: usize = 30;
		const INITIAL_SCORE: u128 = 1000;

		let ops_raw = [
			// 0 + 15 + 154 + 165 + 0 + 123 + 56 + 222 + 253 + 12 = 1000
			[0, 15, 154, 165, 0, 123, 56, 222, 253, 12], // - Peer 0 opinions
			// 210 + 0 + 10 + 210 + 20 + 10 + 20 + 30 + 440 + 50 = 1000
			[210, 0, 10, 210, 20, 10, 20, 30, 440, 50], // - Peer 1 opinions
			// 40 + 10 + 0 + 20 + 30 + 410 + 20 + 445 + 23 + 2 = 1000
			[40, 10, 0, 20, 30, 410, 20, 445, 23, 2], // - Peer 2 opinions
			// 10 + 18 + 20 + 0 + 310 + 134 + 45 + 12 + 439 + 12 = 1000
			[10, 18, 20, 0, 310, 134, 45, 12, 439, 12], // - Peer 3 opinions
			// 30 + 130 + 44 + 210 + 0 + 12 + 445 + 62 + 12 + 55 = 1000
			[30, 130, 44, 210, 0, 12, 445, 62, 12, 55], // = Peer 4 opinions
			[0, 15, 154, 165, 123, 0, 56, 222, 253, 12], // - Peer 5 opinions
			[210, 20, 10, 210, 20, 10, 0, 30, 440, 50], // - Peer 6 opinions
			[40, 10, 445, 20, 30, 410, 20, 0, 23, 2],   // - Peer 7 opinions
			[10, 18, 20, 439, 310, 134, 45, 12, 0, 12], // - Peer 8 opinions
			[30, 130, 44, 210, 55, 12, 445, 62, 12, 0], // = Peer 9 opinions
		];

		let ops = ops_raw.map(|arr| arr.map(|x| Fr::from_u128(x)).to_vec()).to_vec();

		let start = Instant::now();

		let _ =
			eigen_trust_set_testing_helper::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(ops);

		let end = start.elapsed();
		println!("Convergence time: {:?}", end);
	}
}
