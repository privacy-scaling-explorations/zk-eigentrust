// Rns
// bit_len_lookup: 17,
// wrong_modulus:
// 21888242871839275222246405745257275088696311157297823662689037894645226208583,
// native_modulus:
// 21888242871839275222246405745257275088548364400416034343698204186575808495617,
// binary_modulus:
// 7588550360256754183279148073529370729071901715047420004889892225542594864082845696,
// crt_modulus:
// 166100033330483263771891769974495097228807904130411393260304576971769623221437250863502951190734612532350192541290114096968998888229427253981337422670103314432,
// right_shifters: [
//     0x0000000000000000000000000000000000000000000000000000000000000001,
//     0x0b603a5609b3f6f81dbc9c192fc7933ab42e346981868e480f8e4610fb396ee5,
//     0x1b7c016fe8acfaed1a908db2cea9b991a31a140f219532a9568bea8e0766f9dd,
//     0x0523513296c10199338287b1e0bedd9955a33201cd88df51769b0bf04e2f27cc,
// ],
// left_shifters: [
//     0x0000000000000000000000000000000000000000000000000000000000000001,
//     0x0000000000000000000000000000000000000000000000100000000000000000,
//     0x0000000000000000000000000000010000000000000000000000000000000000,
//     0x0000000000001000000000000000000000000000000000000000000000000000,
// ],
// base_aux: [
//     488280579659007654542,
//     510955945554286098768,
//     301160387202582250159,
//     1702635872462387,
// ],
// negative_wrong_modulus_decomposed: [
//     0x000000000000000000000000000000000000000000000002c3df73e9278302b9,
//     0x00000000000000000000000000000000000000000000000a2687e956e978e357,
//     0x00000000000000000000000000000000000000000000000fd647afba497e7ea7,
//     0x00000000000000000000000000000000000000000000000ffffcf9bb18d1ece5,
// ],
// wrong_modulus_decomposed: [
//     0x00000000000000000000000000000000000000000000000d3c208c16d87cfd47,
//     0x000000000000000000000000000000000000000000000005d97816a916871ca8,
//     0x00000000000000000000000000000000000000000000000029b85045b6818158,
//     0x00000000000000000000000000000000000000000000000000030644e72e131a,
// ],
// wrong_modulus_minus_one: [
//     0x00000000000000000000000000000000000000000000000d3c208c16d87cfd46,
//     0x000000000000000000000000000000000000000000000005d97816a916871ca8,
//     0x00000000000000000000000000000000000000000000000029b85045b6818158,
//     0x00000000000000000000000000000000000000000000000000030644e72e131a,
// ],
// wrong_modulus_in_native_modulus:
// 0x000000000000000000000000000000006f4d8248eeb859fbf83e9682e87cfd46,
// max_reduced_limb: 295147905179352825855,
// max_unreduced_limb: 5070602400912917605986812821503,
// max_remainder:
// 28948022309329048855892746252171976963317496166410141009864396001978282409983,
// max_operand:
// 7410693711188236507108543040556026102609279018600996098525285376506440296955903,
// max_mul_quotient:
// 3794275180128377091639574036764685364535950857523710002444946112771297432041422847,
// max_most_significant_reduced_limb: 1125899906842623,
// max_most_significant_operand_limb: 288230376151711743,
// max_most_significant_mul_quotient_limb: 147573952589676412927,
// mul_v_bit_len: 71,
// red_v_bit_len: 69,

use super::native::Integer;
use halo2::{
	arithmetic::{Field, FieldExt},
	halo2curves::bn256::{Fq, Fr},
	plonk::Expression,
};
use num_bigint::BigUint;
use num_integer::Integer as BigInteger;
use num_traits::{FromPrimitive, Num, One, Zero};
use std::{fmt::Debug, ops::Shl, str::FromStr};

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
	/// Returns residue value from given inputs.
	fn residues(n: &[N; NUM_LIMBS], t: &[N; NUM_LIMBS]) -> Vec<N>;
	/// Returns `quotient` and `remainder` for the reduce operation.
	fn construct_reduce_qr(a_bn: BigUint) -> (N, [N; NUM_LIMBS]);
	/// Returns `quotient` and `remainder` for the add operation.
	fn construct_add_qr(a_bn: BigUint, b_bn: BigUint) -> (N, [N; NUM_LIMBS]);
	/// Returns `quotient` and `remainder` for the sub operation.
	fn construct_sub_qr(a_bn: BigUint, b_bn: BigUint) -> (N, [N; NUM_LIMBS]);
	/// Returns `quotient` and `remainder` for the mul operation.
	fn construct_mul_qr(a_bn: BigUint, b_bn: BigUint) -> ([N; NUM_LIMBS], [N; NUM_LIMBS]);
	/// Returns `quotient` and `remainder` for the div operation.
	fn construct_div_qr(a_bn: BigUint, b_bn: BigUint) -> ([N; NUM_LIMBS], [N; NUM_LIMBS]);
	/// Constraint for the binary part of `Chinese Remainder Theorem`.
	fn constrain_binary_crt(t: [N; NUM_LIMBS], result: [N; NUM_LIMBS], residues: Vec<N>) -> bool;
	/// Constraint for the binary part of `Chinese Remainder Theorem` using
	/// Expressions.
	fn constrain_binary_crt_exp(
		t: [Expression<N>; NUM_LIMBS], result: [Expression<N>; NUM_LIMBS],
		residues: Vec<Expression<N>>,
	) -> Vec<Expression<N>>;
	/// Composes integer limbs into single [`FieldExt`] value.
	fn compose(input: [N; NUM_LIMBS]) -> N;
	/// Composes integer limbs as Expressions into single Expression value.
	fn compose_exp(input: [Expression<N>; NUM_LIMBS]) -> Expression<N>;
	/// Inverts given Integer.
	fn invert(input: BigUint) -> Option<Integer<W, N, NUM_LIMBS, NUM_BITS, Self>>;
}

/// Returns modulus of the [`FieldExt`] as [`BigUint`].
pub fn modulus<F: FieldExt>() -> BigUint {
	BigUint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
}

/// Returns [`FieldExt`] for the given [`BigUint`].
pub fn big_to_fe<F: FieldExt>(e: BigUint) -> F {
	let modulus = modulus::<F>();
	let e = e % modulus;
	F::from_str_vartime(&e.to_str_radix(10)[..]).unwrap()
}

/// Returns [`BigUint`] representation for the given [`FieldExt`].
pub fn fe_to_big<F: FieldExt>(fe: F) -> BigUint {
	BigUint::from_bytes_le(fe.to_repr().as_ref())
}

/// Returns `limbs` by decomposing [`BigUint`].
pub fn decompose_big<F: FieldExt, const NUM_LIMBS: usize, const BIT_LEN: usize>(
	mut e: BigUint,
) -> [F; NUM_LIMBS] {
	let mask = BigUint::from(1usize).shl(BIT_LEN) - 1usize;
	let mut limbs = [F::zero(); NUM_LIMBS];
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

/// Structure for the Bn256_4_68
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Bn256_4_68;

impl RnsParams<Fq, Fr, 4, 68> for Bn256_4_68 {
	fn native_modulus() -> BigUint {
		BigUint::from_str(
			"21888242871839275222246405745257275088548364400416034343698204186575808495617",
		)
		.unwrap()
	}

	fn wrong_modulus() -> BigUint {
		BigUint::from_str(
			"21888242871839275222246405745257275088696311157297823662689037894645226208583",
		)
		.unwrap()
	}

	fn wrong_modulus_in_native_modulus() -> Fr {
		Fr::from_u128(147946756881789318990833708069417712966)
	}

	fn negative_wrong_modulus_decomposed() -> [Fr; 4] {
		let limb0 = Fr::from_u128(51007615349848998585);
		let limb1 = Fr::from_u128(187243884991886189399);
		let limb2 = Fr::from_u128(292141664167738113703);
		let limb3 = Fr::from_u128(295147053861416594661);
		[limb0, limb1, limb2, limb3]
	}

	fn right_shifters() -> [Fr; 4] {
		let limb0 = Fr::from_u128(1);
		let limb1 = Fr::from_raw([
			0xf8e4610fb396ee5, 0xb42e346981868e48, 0x1dbc9c192fc7933a, 0xb603a5609b3f6f8,
		]);
		let limb2 = Fr::from_raw([
			0x568bea8e0766f9dd, 0xa31a140f219532a9, 0x1a908db2cea9b991, 0x1b7c016fe8acfaed,
		]);
		let limb3 = Fr::from_raw([
			0x769b0bf04e2f27cc, 0x55a33201cd88df51, 0x338287b1e0bedd99, 0x523513296c10199,
		]);
		[limb0, limb1, limb2, limb3]
	}

	fn left_shifters() -> [Fr; 4] {
		let limb0 = Fr::from_u128(1);
		let limb1 = Fr::from_raw([0x0, 0x10, 0x0, 0x0]);
		let limb2 = Fr::from_raw([0x0, 0x0, 0x100, 0x0]);
		let limb3 = Fr::from_raw([0x0, 0x0, 0x0, 0x1000]);
		[limb0, limb1, limb2, limb3]
	}

	fn to_add_x() -> [Fr; 4] {
		let limb0 = Fr::from_u128(39166801021317585802);
		let limb1 = Fr::from_u128(280722752500048210634);
		let limb2 = Fr::from_u128(246774286082614522626);
		let limb3 = Fr::from_u128(648543811392721);
		[limb0, limb1, limb2, limb3]
	}

	fn to_add_y() -> [Fr; 4] {
		let limb0 = Fr::from_u128(260479261066082801011);
		let limb1 = Fr::from_u128(36674947070525072812);
		let limb2 = Fr::from_u128(146132927816985441332);
		let limb3 = Fr::from_u128(251381276165850);
		[limb0, limb1, limb2, limb3]
	}

	fn to_sub_x() -> [Fr; 4] {
		let limb0 = Fr::from_u128(39683184256656720731);
		let limb1 = Fr::from_u128(65039279958035916755);
		let limb2 = Fr::from_u128(55471468959241741054);
		let limb3 = Fr::from_u128(517651676279778);
		[limb0, limb1, limb2, limb3]
	}

	fn to_sub_y() -> [Fr; 4] {
		let limb0 = Fr::from_u128(82480000500960897165);
		let limb1 = Fr::from_u128(24667200311316519684);
		let limb2 = Fr::from_u128(293910609844452716081);
		let limb3 = Fr::from_u128(761069265693657);
		[limb0, limb1, limb2, limb3]
	}

	fn residues(n: &[Fr; 4], t: &[Fr; 4]) -> Vec<Fr> {
		let lsh1 = Self::left_shifters()[1];
		let rsh2 = Self::right_shifters()[2];

		let mut res = Vec::new();
		let mut carry = Fr::zero();
		for i in (0..4).step_by(2) {
			let (t_0, t_1) = (t[i], t[i + 1]);
			let (r_0, r_1) = (n[i], n[i + 1]);
			let u = t_0 + (t_1 * lsh1) - r_0 - (lsh1 * r_1) + carry;
			let v = u * rsh2;
			carry = v;
			res.push(v)
		}
		res
	}

	fn construct_reduce_qr(a_bn: BigUint) -> (Fr, [Fr; 4]) {
		let wrong_mod_bn = Self::wrong_modulus();
		let (quotient, result_bn) = a_bn.div_rem(&wrong_mod_bn);
		let q = big_to_fe(quotient);
		let result = decompose_big::<Fr, 4, 68>(result_bn);
		(q, result)
	}

	fn construct_add_qr(a_bn: BigUint, b_bn: BigUint) -> (Fr, [Fr; 4]) {
		let wrong_mod_bn = Self::wrong_modulus();
		let (quotient, result_bn) = (a_bn + b_bn).div_rem(&wrong_mod_bn);
		// This check assures that the addition operation can only wrap the wrong field
		// one time.
		assert!(quotient <= BigUint::from_u8(1).unwrap());
		let q = big_to_fe(quotient);
		let result = decompose_big::<Fr, 4, 68>(result_bn);
		(q, result)
	}

	fn construct_sub_qr(a_bn: BigUint, b_bn: BigUint) -> (Fr, [Fr; 4]) {
		let wrong_mod_bn = Self::wrong_modulus();
		let (quotient, result_bn) = if b_bn > a_bn {
			let negative_result = big_to_fe::<Fq>(a_bn) - big_to_fe::<Fq>(b_bn);
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
		let result = decompose_big::<Fr, 4, 68>(result_bn);
		(q, result)
	}

	fn construct_mul_qr(a_bn: BigUint, b_bn: BigUint) -> ([Fr; 4], [Fr; 4]) {
		let wrong_mod_bn = Self::wrong_modulus();
		let (quotient, result_bn) = (a_bn * b_bn).div_rem(&wrong_mod_bn);
		let q = decompose_big::<Fr, 4, 68>(quotient);
		let result = decompose_big::<Fr, 4, 68>(result_bn);
		(q, result)
	}

	fn construct_div_qr(a_bn: BigUint, b_bn: BigUint) -> ([Fr; 4], [Fr; 4]) {
		let b_invert = Self::invert(b_bn.clone()).unwrap().value();
		let should_be_one = b_invert.clone() * b_bn.clone() % Self::wrong_modulus();
		assert!(should_be_one == BigUint::one());
		let result = b_invert * a_bn.clone() % Self::wrong_modulus();
		let (quotient, reduced_self) = (result.clone() * b_bn).div_rem(&Self::wrong_modulus());
		let (k, must_be_zero) = (a_bn - reduced_self).div_rem(&Self::wrong_modulus());
		assert_eq!(must_be_zero, BigUint::zero());
		let q = decompose_big::<Fr, 4, 68>(quotient - k);
		let result = decompose_big::<Fr, 4, 68>(result);
		(q, result)
	}

	fn constrain_binary_crt(t: [Fr; 4], result: [Fr; 4], residues: Vec<Fr>) -> bool {
		let lsh_one = Self::left_shifters()[1];
		let lsh_two = Self::left_shifters()[2];

		let mut is_satisfied = true;
		let mut v = Fr::zero();
		for i in (0..4).step_by(2) {
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

	fn constrain_binary_crt_exp(
		t: [Expression<Fr>; 4], result: [Expression<Fr>; 4], residues: Vec<Expression<Fr>>,
	) -> Vec<Expression<Fr>> {
		let lsh_one = Self::left_shifters()[1];
		let lsh_two = Self::left_shifters()[2];

		let mut v = Expression::Constant(Fr::zero());
		let mut constraints = Vec::new();
		for i in (0..4).step_by(2) {
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
	fn compose(input: [Fr; 4]) -> Fr {
		let left_shifters = Self::left_shifters();
		let mut sum = Fr::zero();
		for i in 0..4 {
			sum += input[i] * left_shifters[i];
		}
		sum
	}

	fn compose_exp(input: [Expression<Fr>; 4]) -> Expression<Fr> {
		let left_shifters = Self::left_shifters();
		let mut sum = Expression::Constant(Fr::zero());
		for i in 0..4 {
			sum = sum + input[i].clone() * left_shifters[i];
		}
		sum
	}

	// TODO: Move outside Rns -- Use just BigUint as output
	/// Computes the inverse of the [`BigUint`] as an element of the Wrong
	/// field. Returns `None` if the value cannot be inverted.
	fn invert(input: BigUint) -> Option<Integer<Fq, Fr, 4, 68, Bn256_4_68>> {
		let a_w = big_to_fe::<Fq>(input);
		let inv_w = a_w.invert();
		inv_w.map(|inv| Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(fe_to_big(inv))).into()
	}
}
