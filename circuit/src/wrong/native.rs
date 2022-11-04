#![allow(missing_docs)]
use std::marker::PhantomData;

use super::rns::{compose, decompose_big, fe_to_big, RnsParams};
use halo2wrong::halo2::arithmetic::FieldExt;
use num_bigint::BigUint;

#[derive(Clone)]
enum Quotient<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	Add(N),
	Mul(Integer<W, N, NUM_LIMBS, NUM_BITS, P>),
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	Quotient<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	pub fn add(self) -> N {
		match self {
			Quotient::Add(res) => res,
			_ => panic!("Not add Quotient"),
		}
	}

	pub fn mul(self) -> Integer<W, N, NUM_LIMBS, NUM_BITS, P> {
		match self {
			Quotient::Mul(res) => res,
			_ => panic!("Not add Quotient"),
		}
	}
}

struct ReductionWitness<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	result: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
	quotient: Quotient<W, N, NUM_LIMBS, NUM_BITS, P>,
	intermediate: [N; NUM_LIMBS],
	residues: Vec<N>,
}

#[derive(Debug, Clone)]
struct Integer<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	pub(crate) limbs: [N; NUM_LIMBS],
	_wrong_field: PhantomData<W>,
	_rns: PhantomData<P>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	Integer<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	pub fn new(num: BigUint) -> Self {
		let limbs = decompose_big::<N, NUM_LIMBS, NUM_BITS>(num);
		Self::from_limbs(limbs)
	}

	pub fn from_limbs(limbs: [N; NUM_LIMBS]) -> Self {
		Self { limbs, _wrong_field: PhantomData, _rns: PhantomData }
	}

	pub fn value(&self) -> BigUint {
		let limb_values = self.limbs.map(|limb| fe_to_big(limb));
		compose::<NUM_LIMBS, NUM_BITS>(limb_values)
	}

	pub fn add(
		&self, other: &Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
	) -> ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P> {
		let p_prime = P::negative_wrong_modulus_decomposed();
		let a = self.value();
		let b = other.value();
		let (q, res) = P::construct_add_qr(a, b);

		let mut t = [N::zero(); NUM_LIMBS];
		for i in 0..NUM_LIMBS {
			t[i] = self.limbs[i] + other.limbs[i] + p_prime[i] * q;
		}

		let residues = P::residues(&res, &t);

		let result_int = Integer::from_limbs(res);
		let quotient_n = Quotient::Add(q);
		ReductionWitness { result: result_int, quotient: quotient_n, intermediate: t, residues }
	}

	pub fn mul(
		&self, other: &Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
	) -> ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P> {
		let p_prime = P::negative_wrong_modulus_decomposed();
		let a = self.value();
		let b = other.value();
		let (q, res) = P::construct_mul_qr(a, b);

		let mut t: [N; NUM_LIMBS] = [N::zero(); NUM_LIMBS];
		for k in 0..NUM_LIMBS {
			for i in 0..=k {
				let j = k - i;
				t[i + j] = t[i + j] + self.limbs[i] * other.limbs[j] + p_prime[i] * q[j];
			}
		}

		let residues = P::residues(&res, &t);

		let result_int = Integer::from_limbs(res);
		let quotient_int = Quotient::Mul(Integer::from_limbs(q));
		ReductionWitness { result: result_int, quotient: quotient_int, intermediate: t, residues }
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::wrong::rns::Bn256_4_68;
	use halo2wrong::curves::bn256::{Fq, Fr};
	use num_integer::Integer as NumInteger;
	use num_traits::{FromPrimitive, Zero};
	use std::str::FromStr;

	#[test]
	fn should_mul_two_numbers() {}

	#[test]
	fn should_mul_accumulate_array_of_small_numbers() {
		// [1, 2, 3, 4, 5, 6, 7, 8]
	}

	#[test]
	fn should_mul_accumulate_array_of_big_numbers() {
		// [2^247, 2^248, 2^249, 2^250, 2^251, 2^252, 2^253, 2^254]
	}

	#[test]
	fn should_add_two_numbers() {
		let a_big = Bn256_4_68::wrong_modulus() - BigUint::from_u8(1).unwrap();
		let b_big = Bn256_4_68::wrong_modulus() - BigUint::from_u8(1).unwrap();
		let big_answer = (a_big.clone() + b_big.clone()).mod_floor(&Bn256_4_68::wrong_modulus());
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let b = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_big);
		let c = a.add(&b);
		// TODO: FIX REDUCE CONSTRAINTS
		let p_prime = Bn256_4_68::negative_wrong_modulus_decomposed();
		let q = c.quotient.clone().add();
		for i in 0..4 {
			let con = c.result.limbs[i] + q * p_prime[i];
			println!("con {:?}", con);
		}
		let val = Bn256_4_68::constrain_binary_crt(c.intermediate, c.result.limbs, c.residues);
		assert_eq!(c.result.value(), big_answer);
	}

	// #[test]
	// fn should_add_accumulate_array_of_small_numbers() {
	// 	// [1, 2, 3, 4, 5, 6, 7, 8]
	// 	let a_big = [(); 8].map(|_| BigUint::from_str("7961293874321").unwrap());
	// 	let mut acc = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(BigUint::zero());
	// 	let mut big_answer = BigUint::zero();
	// 	for i in 0..8 {
	// 		big_answer += a_big[i].clone();
	// 		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big[i].clone());
	// 		acc = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::add(&acc, &a);
	// 	}
	// 	assert_eq!(acc.value(), big_answer);
	// }

	// #[test]
	// fn should_add_accumulate_array_of_big_numbers() {
	// 	// [2^247, 2^248, 2^249, 2^250, 2^251, 2^252, 2^253, 2^254]
	// 	// Accumulate with BigUint
	// 	// Accumulate with Integer - compose and compare
	// }
}
