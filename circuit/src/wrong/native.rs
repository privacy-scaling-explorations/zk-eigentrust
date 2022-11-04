#![allow(missing_docs)]
use std::marker::PhantomData;

use super::rns::{compose, decompose_big, fe_to_big, RnsParams};
use halo2wrong::halo2::arithmetic::FieldExt;
use num_bigint::BigUint;

struct ReductionWitness<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	result: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
	quotient: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
	intermediate: [N; NUM_LIMBS],
	residues: Vec<N>,
}
#[derive(Debug)]
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

	pub fn add(&self, other: &Integer<W, N, NUM_LIMBS, NUM_BITS, P>) -> Self {
		let mut res: [N; NUM_LIMBS] = [N::zero(); NUM_LIMBS];
		for i in 0..NUM_LIMBS {
			res[i] = self.limbs[i] + other.limbs[i];
		}
		Self::from_limbs(res)
	}

	pub fn mul(
		&self, other: &Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
	) -> ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P> {
		let p_prime = P::negative_wrong_modulus_decomposed();
		let a = self.value();
		let b = other.value();
		let (q, res) = P::get_qr(a, b);

		let mut t: [N; NUM_LIMBS] = [N::zero(); NUM_LIMBS];
		for k in 0..NUM_LIMBS {
			for i in 0..=k {
				let j = k - i;
				t[i + j] = t[i + j] + self.limbs[i] * other.limbs[j] + p_prime[i] * q[j];
			}
		}

		let residues = P::residues(&res, &t);

		let result_int = Integer::from_limbs(res);
		let quotient_int = Integer::from_limbs(q);
		ReductionWitness { result: result_int, quotient: quotient_int, intermediate: t, residues }
	}
}

#[cfg(test)]
mod test {
	use halo2wrong::curves::bn256::{Fq, Fr};
use num_traits::Zero;
	use super::*;
	use std::str::FromStr;
	use crate::wrong::rns::Bn256_4_68;

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
		let a_big = BigUint::from_str("79187419823874321").unwrap();
		let b_big = BigUint::from_str("187187437437437491874198238791874198238791874198238791874198238791874198238791874198238737419821874193419818741982323").unwrap();
		let big_answer = a_big.clone() + b_big.clone();
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let b = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_big);
		let c = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::add(&a, &b);
		assert_eq!(c.value(), big_answer);
	}

	#[test]
	fn should_add_accumulate_array_of_small_numbers() {
		// [1, 2, 3, 4, 5, 6, 7, 8]
		let a_big = [(); 8].map(|_| BigUint::from_str("7961293874321").unwrap());
		let mut acc = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(BigUint::zero());
		let mut big_answer = BigUint::zero();
		for i in 0..8{
		big_answer += a_big[i].clone();
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big[i].clone());
		acc = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::add(&acc, &a);
		}
		assert_eq!(acc.value(), big_answer);
	}

	#[test]
	fn should_add_accumulate_array_of_big_numbers() {
		// [2^247, 2^248, 2^249, 2^250, 2^251, 2^252, 2^253, 2^254]
		// Accumulate with BigUint
		// Accumulate with Integer - compose and compare
	}
}
