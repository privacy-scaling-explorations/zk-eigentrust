use crate::{
	integer::native::Integer,
	utils::{big_to_fe, fe_to_big},
	FieldExt,
};
use halo2::{
	halo2curves::{
		bn256::Fr,
		group::{ff::PrimeField, Curve},
		CurveAffine,
	},
	plonk::Expression,
};
use num_bigint::BigUint;
use num_integer::Integer as BigInteger;
use num_traits::{FromPrimitive, One, Zero};
use std::{
	fmt::Debug,
	ops::{Shl, Sub},
	str::FromStr,
};

/// BN256 curve RNS params
pub mod bn256;
/// Secp256K1 curve RNS params
pub mod secp256k1;

pub(crate) fn make_mul_aux<C: CurveAffine>(aux_to_add: C) -> C
where
	C::Scalar: FieldExt,
{
	let n = <C::Scalar>::NUM_BITS as usize;
	let mut k0 = BigUint::one();
	let one = BigUint::one();
	for i in 0..n {
		k0 |= &one << i;
	}
	(-aux_to_add * big_to_fe::<C::Scalar>(k0.sub(BigUint::one()))).to_affine()
}

/// This trait is for the dealing with RNS operations.
pub trait RnsParams<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize>:
	Clone + Debug + PartialEq + Default
{
	/// Returns Scalar (Native) Field modulus [`Fr`] from Bn256.
	fn native_modulus() -> BigUint;
	/// Returns Base (Wrong) Field modulus [`Fq`] from Bn256.
	fn wrong_modulus() -> BigUint;
	/// Returns wrong modulus in native modulus.
	fn wrong_modulus_in_native_modulus() -> N;
	/// Returns negative Base (Wrong) Field as decomposed.
	fn negative_wrong_modulus_decomposed() -> [N; NUM_LIMBS];
	/// Returns right shifters.
	fn right_shifters() -> [N; NUM_LIMBS];
	/// Returns left shifters.
	fn left_shifters() -> [N; NUM_LIMBS];
	/// Returns EcPoint AuxInit's x coordinate
	fn to_add_x() -> [N; NUM_LIMBS];
	/// Returns EcPoint AuxInit's y coordinate
	fn to_add_y() -> [N; NUM_LIMBS];
	/// Returns EcPoint AuxFin's x coordinate
	fn to_sub_x() -> [N; NUM_LIMBS];
	/// Returns EcPoint AuxFin's y coordinate
	fn to_sub_y() -> [N; NUM_LIMBS];
	/// Inverts given Integer.
	fn invert(input: BigUint) -> Option<Integer<W, N, NUM_LIMBS, NUM_BITS, Self>> {
		let a_w = big_to_fe::<W>(input);
		let inv_w = a_w.invert();
		inv_w.map(|inv| Integer::<W, N, NUM_LIMBS, NUM_BITS, Self>::new(fe_to_big(inv))).into()
	}

	/// Returns residue value from given inputs.
	fn residues(n: &[N; NUM_LIMBS], t: &[N; NUM_LIMBS]) -> Vec<N> {
		let lsh1 = Self::left_shifters()[1];
		let rsh2 = Self::right_shifters()[2];

		let mut res = Vec::new();
		let mut carry = N::ZERO;
		for i in (0..NUM_LIMBS).step_by(2) {
			let (t_0, t_1) = (t[i], t[i + 1]);
			let (r_0, r_1) = (n[i], n[i + 1]);
			let u = t_0 + (t_1 * lsh1) - r_0 - (lsh1 * r_1) + carry;
			let v = u * rsh2;
			carry = v;
			res.push(v)
		}
		res
	}

	/// Returns `quotient` and `remainder` for the reduce operation.
	fn construct_reduce_qr(a_bn: BigUint) -> (N, [N; NUM_LIMBS]) {
		let wrong_mod_bn = Self::wrong_modulus();
		let (quotient, result_bn) = a_bn.div_rem(&wrong_mod_bn);
		let q = big_to_fe(quotient);
		let result = decompose_big::<N, NUM_LIMBS, NUM_BITS>(result_bn);
		(q, result)
	}

	/// Returns `quotient` and `remainder` for the add operation.
	fn construct_add_qr(a_bn: BigUint, b_bn: BigUint) -> (N, [N; NUM_LIMBS]) {
		let wrong_mod_bn = Self::wrong_modulus();
		let (quotient, result_bn) = (a_bn + b_bn).div_rem(&wrong_mod_bn);
		// This check assures that the addition operation can only wrap the wrong field
		// one time.
		assert!(quotient <= BigUint::from_u8(1).unwrap());
		let q = big_to_fe(quotient);
		let result = decompose_big::<N, NUM_LIMBS, NUM_BITS>(result_bn);
		(q, result)
	}

	/// Returns `quotient` and `remainder` for the sub operation.
	fn construct_sub_qr(a_bn: BigUint, b_bn: BigUint) -> (N, [N; NUM_LIMBS]) {
		let wrong_mod_bn = Self::wrong_modulus();
		let (quotient, result_bn) = if b_bn > a_bn {
			let negative_result = big_to_fe::<W>(a_bn) - big_to_fe::<W>(b_bn);
			let (_, result_bn) = (fe_to_big(negative_result)).div_rem(&wrong_mod_bn);
			// This quotient is considered as -1 in calculations.
			let quotient = BigUint::from_i8(1).unwrap();
			(quotient, result_bn)
		} else {
			(a_bn - b_bn).div_rem(&wrong_mod_bn)
		};
		// This check assures that the subtraction operation can only wrap the wrong
		// field one time.
		assert!(quotient <= BigUint::from_u8(1).unwrap());
		let q = big_to_fe(quotient);
		let result = decompose_big::<N, NUM_LIMBS, NUM_BITS>(result_bn);
		(q, result)
	}

	/// Returns `quotient` and `remainder` for the mul operation.
	fn construct_mul_qr(a_bn: BigUint, b_bn: BigUint) -> ([N; NUM_LIMBS], [N; NUM_LIMBS]) {
		let wrong_mod_bn = Self::wrong_modulus();
		let (quotient, result_bn) = (a_bn * b_bn).div_rem(&wrong_mod_bn);
		let q = decompose_big::<N, NUM_LIMBS, NUM_BITS>(quotient);
		let result = decompose_big::<N, NUM_LIMBS, NUM_BITS>(result_bn);
		(q, result)
	}

	/// Returns `quotient` and `remainder` for the div operation.
	fn construct_div_qr(a_bn: BigUint, b_bn: BigUint) -> ([N; NUM_LIMBS], [N; NUM_LIMBS]) {
		let b_invert = Self::invert(b_bn.clone()).unwrap().value();
		let should_be_one = b_invert.clone() * b_bn.clone() % Self::wrong_modulus();
		assert!(should_be_one == BigUint::one());
		let result = b_invert * a_bn.clone() % Self::wrong_modulus();
		let (quotient, reduced_self) = (result.clone() * b_bn).div_rem(&Self::wrong_modulus());
		let (k, must_be_zero) = (a_bn - reduced_self).div_rem(&Self::wrong_modulus());
		assert_eq!(must_be_zero, BigUint::zero());
		let q = decompose_big::<N, NUM_LIMBS, NUM_BITS>(quotient - k);
		let result = decompose_big::<N, NUM_LIMBS, NUM_BITS>(result);
		(q, result)
	}

	/// Constraint for the binary part of `Chinese Remainder Theorem`.
	fn constrain_binary_crt(t: [N; NUM_LIMBS], result: [N; NUM_LIMBS], residues: Vec<N>) -> bool {
		let lsh_one = Self::left_shifters()[1];
		let lsh_two = Self::left_shifters()[2];

		let mut is_satisfied = true;
		let mut v = N::ZERO;
		for i in (0..NUM_LIMBS).step_by(2) {
			let (t_lo, t_hi) = (t[i], t[i + 1]);
			let (r_lo, r_hi) = (result[i], result[i + 1]);
			// CONSTRAINT
			let res = t_lo + t_hi * lsh_one - r_lo - r_hi * lsh_one - residues[i / 2] * lsh_two + v;
			v = residues[i / 2];
			let res_is_zero: bool = res.is_zero().into();
			is_satisfied = is_satisfied & res_is_zero;
		}
		is_satisfied
	}

	/// Constraint for the binary part of `Chinese Remainder Theorem` using
	/// Expressions.
	fn constrain_binary_crt_exp(
		t: [Expression<N>; NUM_LIMBS], result: [Expression<N>; NUM_LIMBS],
		residues: Vec<Expression<N>>,
	) -> Vec<Expression<N>> {
		let lsh_one = Self::left_shifters()[1];
		let lsh_two = Self::left_shifters()[2];

		let mut v = Expression::Constant(N::ZERO);
		let mut constraints = Vec::new();
		for i in (0..NUM_LIMBS).step_by(2) {
			let (t_lo, t_hi) = (t[i].clone(), t[i + 1].clone());
			let (r_lo, r_hi) = (result[i].clone(), result[i + 1].clone());
			let res =
				t_lo + t_hi * lsh_one - r_lo - r_hi * lsh_one - residues[i / 2].clone() * lsh_two
					+ v;
			v = residues[i / 2].clone();
			constraints.push(res);
		}

		constraints
	}

	/// Composes integer limbs into single [`FieldExt`] value.
	fn compose(input: [N; NUM_LIMBS]) -> N {
		let left_shifters = Self::left_shifters();
		let mut sum = N::ZERO;
		for i in 0..NUM_LIMBS {
			sum += input[i] * left_shifters[i];
		}
		sum
	}

	/// Composes integer limbs as Expressions into single Expression value.
	fn compose_exp(input: [Expression<N>; NUM_LIMBS]) -> Expression<N> {
		let left_shifters = Self::left_shifters();
		let mut sum = Expression::Constant(N::ZERO);
		for i in 0..NUM_LIMBS {
			sum = sum + input[i].clone() * left_shifters[i];
		}
		sum
	}
}

/// Returns `limbs` by decomposing [`BigUint`].
pub fn decompose_big<F: FieldExt, const NUM_LIMBS: usize, const BIT_LEN: usize>(
	mut e: BigUint,
) -> [F; NUM_LIMBS] {
	let mask = BigUint::from(1usize).shl(BIT_LEN) - 1usize;
	let mut limbs = [F::ZERO; NUM_LIMBS];
	for i in 0..NUM_LIMBS {
		let limb = mask.clone() & e.clone();
		e = e.clone() >> BIT_LEN;
		limbs[i] = big_to_fe(limb);
	}
	limbs
}

/// Returns [`BigUint`] by composing `limbs`.
pub fn compose_big<const NUM_LIMBS: usize, const NUM_BITS: usize>(
	input: [BigUint; NUM_LIMBS],
) -> BigUint {
	let mut res = BigUint::zero();
	for i in (0..NUM_LIMBS).rev() {
		res = (res << NUM_BITS) + input[i].clone();
	}
	res
}
