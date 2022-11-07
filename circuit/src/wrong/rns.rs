#![allow(missing_docs)]
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

use std::{result, str::FromStr};

use halo2wrong::{
	curves::{
		bn256::{Fq, Fr},
		group::ff::PrimeField,
	},
	halo2::arithmetic::{Field, FieldExt},
};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{FromPrimitive, Num, Zero};
use std::ops::Shl;

pub trait RnsParams<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize> {
	fn native_modulus() -> BigUint;
	fn wrong_modulus() -> BigUint;
	fn negative_wrong_modulus_decomposed() -> [N; NUM_LIMBS];
	fn right_shifters() -> [N; NUM_LIMBS];
	fn left_shifters() -> [N; NUM_LIMBS];
	fn max_reduced_limb() -> N;
	fn max_unreduced_limb() -> N;
	fn max_remainder() -> BigUint;
	fn residues(n: &[N; NUM_LIMBS], t: &[N; NUM_LIMBS]) -> Vec<N>;
	fn construct_mul_qr(a_bn: BigUint, b_bn: BigUint) -> ([N; NUM_LIMBS], [N; NUM_LIMBS]);
	fn construct_add_qr(a_bn: BigUint, b_bn: BigUint) -> (N, [N; NUM_LIMBS]);
	fn constrain_binary_crt(t: [N; 4], result: [N; 4], residues: Vec<N>) -> bool;
}

pub fn modulus<F: FieldExt>() -> BigUint {
	BigUint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
}

pub fn big_to_fe<F: FieldExt>(e: BigUint) -> F {
	let modulus = modulus::<F>();
	let e = e % modulus;
	F::from_str_vartime(&e.to_str_radix(10)[..]).unwrap()
}

pub fn fe_to_big<F: FieldExt>(fe: F) -> BigUint {
	BigUint::from_bytes_le(fe.to_repr().as_ref())
}

pub fn decompose_big<F: FieldExt, const NUM_LIMBS: usize, const BIT_LEN: usize>(
	mut e: BigUint,
) -> [F; NUM_LIMBS] {
	let mask = BigUint::from(1usize).shl(BIT_LEN) - 1usize;
	let mut limbs = [F::zero(); NUM_LIMBS];
	for i in 0..NUM_LIMBS {
		let limb = mask.clone() & e.clone();
		e = e.clone() >> BIT_LEN;
		//println!("{}", limb.to_str_radix(16));
		limbs[i] = big_to_fe(limb);
	}

	limbs
}

pub fn compose<const NUM_LIMBS: usize, const NUM_BITS: usize>(
	input: [BigUint; NUM_LIMBS],
) -> BigUint {
	let mut res = BigUint::zero();
	for i in (0..NUM_LIMBS).rev() {
		res = (res << NUM_BITS) + input[i].clone();
	}
	res
}

pub fn terms_compose(input: Vec<Fr>, quotient: Fr) -> Fr{
	let input: Vec<Fr> = input.iter().filter(|e| !bool::from(e.is_zero())).cloned().collect();
	let mut result = Fr::zero();
	for i in 0..input.len(){
		if quotient == Fr::zero() {
			result = result + input[i];
		}
		else {
		result = result + (input[i] * quotient);
		}		
	}
	result
}

#[derive(Debug, Clone)]
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

	fn max_reduced_limb() -> Fr {
		Fr::from_u128(295147905179352825855)
	}

	fn max_unreduced_limb() -> Fr {
		Fr::from_u128(5070602400912917605986812821503)
	}

	fn max_remainder() -> BigUint {
		BigUint::from_str(
			"28948022309329048855892746252171976963317496166410141009864396001978282409983",
		)
		.unwrap()
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

	fn construct_mul_qr(a_bn: BigUint, b_bn: BigUint) -> ([Fr; 4], [Fr; 4]) {
		let wrong_mod_bn = Self::wrong_modulus();
		let (quotient, result_bn) = (a_bn * b_bn).div_rem(&wrong_mod_bn);
		let q = decompose_big::<Fr, 4, 68>(quotient);
		let result = decompose_big::<Fr, 4, 68>(result_bn);
		(q, result)
	}

	fn construct_add_qr(a_bn: BigUint, b_bn: BigUint) -> (Fr, [Fr; 4]) {
		let wrong_mod_bn = Self::wrong_modulus();
		let (quotient, result_bn) = (a_bn + b_bn).div_rem(&wrong_mod_bn);
		assert!(quotient <= BigUint::from_u8(1).unwrap());
		let q = big_to_fe(quotient);
		let result = decompose_big::<Fr, 4, 68>(result_bn);
		(q, result)
	}

	// USED FOR TESTING PURPOSES
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
			is_satisfied = is_satisfied | res_is_zero;
		}

		is_satisfied
	}
}

#[cfg(test)]
mod test {
	use super::*;

	fn residues(n: &[Fr; 4], t: &[Fr; 4]) -> Vec<Fr> {
		let lsh1 = Bn256_4_68::left_shifters()[1];
		let rsh2 = Bn256_4_68::right_shifters()[2];

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

	fn constrain_residues(t: [Fr; 4], result: [Fr; 4], residues: Vec<Fr>) {
		let lsh_one = Bn256_4_68::left_shifters()[1];
		let lsh_two = Bn256_4_68::left_shifters()[2];

		let mut v = Fr::zero();
		for i in (0..4).step_by(2) {
			let (t_lo, t_hi) = (t[i], t[i + 1]);
			let (r_lo, r_hi) = (result[i], result[i + 1]);

			// CONSTRAINT
			let res = t_lo + t_hi * lsh_one - r_lo - r_hi * lsh_one - residues[i / 2] * lsh_two + v;
			v = residues[i / 2];
			//println!("Binary part constraint {:?}", res);
		}
	}

	#[test]
	pub fn wrong_mul() {
		let native_mod_bn = Bn256_4_68::native_modulus();
		let wrong_mod_bn = Bn256_4_68::wrong_modulus();
		let p_prime = Bn256_4_68::negative_wrong_modulus_decomposed();

		let a_bn = BigUint::from_str(
			"91888242871839275222246405745257275088548364400416034343698204186575808495807",
		)
		.unwrap();
		let b_bn = BigUint::from_u64(123134).unwrap();
		let (quotient, result_bn) = (a_bn.clone() * b_bn.clone()).div_rem(&wrong_mod_bn);

		let a = decompose_big::<Fr, 4, 68>(a_bn.clone());
		let b = decompose_big::<Fr, 4, 68>(b_bn.clone());
		let q = decompose_big::<Fr, 4, 68>(quotient.clone());
		let result = decompose_big::<Fr, 4, 68>(result_bn.clone());
		let p = decompose_big::<Fr, 4, 68>(wrong_mod_bn.clone());

		let mut t: [Fr; 4] = [Fr::zero(); 4];

		for k in 0..4 {
			for i in 0..=k {
				let j = k - i;
				t[i + j] = t[i + j] + a[i] * b[j] + p_prime[i] * q[j];
			}
		}

		let residues = residues(&result, &t);

		// a = 8
		// b = 3
		// p = 13
		// n = 5

		// a_native = a % 5
		// b_native = b % 5
		// p_native = p % 5

		let mut new_t: Vec<Fr> = vec![];
		for (i, inter) in t.iter().enumerate() {
			let mut inter = *inter;
			for j in 0..=i {
				let k = i - j;

				let prev_inter = inter;
				let next_inter = inter - (a[j] * b[k] + q[k] * p_prime[j]);

				if j == 0 {
					new_t.push(prev_inter);
				}
				// CONSTRAINT
				println!(
					"{:?}",
					a[j] * b[k] + q[k] * p_prime[j] - prev_inter + next_inter
				);

				inter = next_inter;
			}
		}

		constrain_residues(new_t.try_into().unwrap(), result, residues);

		let a_native = Fr::from_str_vartime(
			"91888242871839275222246405745257275088548364400416034343698204186575808495807",
		)
		.unwrap();
		let b_native = Fr::from_str_vartime("123134").unwrap();
		let wrong_mod_native = Fr::from_str_vartime(
			"21888242871839275222246405745257275088696311157297823662689037894645226208583",
		)
		.unwrap();
		let res_native = Fr::from_str_vartime(
			"8839498411810231587881575137642804062353405807773865066449658236690677140446",
		)
		.unwrap();
		let q_native = Fr::from_str_vartime("516924").unwrap();

		// CONSTRAINT
		let resa = a_native * b_native - q_native * wrong_mod_native - res_native;
		//println!("native {:?}", resa);
	}

	#[test]
	fn reduce() {
		let native_mod_bn = Bn256_4_68::native_modulus();
		let wrong_mod_bn = Bn256_4_68::wrong_modulus();
		let p_prime = Bn256_4_68::negative_wrong_modulus_decomposed();

		let val = BigUint::from_str(
			"91888242871839275222246405745257275088548364400416034343698204186575808495807",
		)
		.unwrap();
		let (quotient, result_bn) = val.div_rem(&wrong_mod_bn);
		assert!(quotient < BigUint::from_u8(1).unwrap() << 68u8.into());

		let q_native = big_to_fe::<Fr>(quotient);
		let result_limbs = decompose_big::<Fr, 4, 68>(result_bn.clone());
		let val_limbs = decompose_big::<Fr, 4, 68>(val);

		let mut t = [Fr::zero(); 4];
		for i in 0..4 {
			let res = val_limbs[i] + p_prime[i] * q_native;
			t[i] = res;
		}

		let residues = residues(&result_limbs, &t);

		// Binary Constraint
		constrain_residues(t.try_into().unwrap(), result_limbs, residues);

		let val_native = Fr::from_str_vartime(
			"91888242871839275222246405745257275088548364400416034343698204186575808495807",
		)
		.unwrap();
		let quotient_native = Fr::from_str_vartime("4").unwrap();
		let wrong_mod_native = Fr::from_str_vartime(
			"21888242871839275222246405745257275088696311157297823662689037894645226208583",
		)
		.unwrap();
		let result_native = big_to_fe::<Fr>(result_bn.clone());
		// Native Constraint
		let reduce_result = quotient_native * wrong_mod_native - val_native + result_native;
		//println!("reduced result = {:?}", reduce_result);
	}

	fn reduce_if_limb_values_exceeds() {
		let num = (BigUint::from_u8(1).unwrap() << 68) - BigUint::from_u8(1).unwrap();
		let max_unreduced = Bn256_4_68::max_unreduced_limb();
		let max_reduced = Bn256_4_68::max_reduced_limb();

		// ADD - If max limb value exceeds max_unreduced_limb
		// MUL - If max limb value exceeds max_reduced_limb
	}

	#[test]
	fn wrong_add() {
		let max_unreduced = Bn256_4_68::max_unreduced_limb();
		//println!("{:?}", max_unreduced);
		let a_bn = BigUint::from_str("7961293874321").unwrap();
		let b_bn = BigUint::from_str("187419823").unwrap();

		let a = decompose_big::<Fr, 4, 68>(a_bn.clone());
		let b = decompose_big::<Fr, 4, 68>(b_bn.clone());

		let mut res: [Fr; 4] = [Fr::zero(); 4];
		for i in 0..4 {
			res[i] = a[i] + b[i];
			//println!("a {}", fe_to_big(a[i]));
			//println!("b {}", fe_to_big(b[i]));
			//println!("res {:#?}", fe_to_big(res[i]));
		}
	}

	#[test]
	fn prepare_nums() {
		let limb1 = Fr::from_str_vartime("295147905179352825856").unwrap();
		let limb2 = Fr::from_str_vartime("87112285931760246646623899502532662132736").unwrap();
		let limb3 =
			Fr::from_str_vartime("25711008708143844408671393477458601640355247900524685364822016")
				.unwrap();
		let limb1_bn = BigUint::from_str("295147905179352825856").unwrap();
		let limb2_bn = BigUint::from_str("87112285931760246646623899502532662132736").unwrap();
		let limb3_bn =
			BigUint::from_str("25711008708143844408671393477458601640355247900524685364822016")
				.unwrap();
		// decompose_big::<Fr, 4, 64>(limb1_bn);
		// decompose_big::<Fr, 4, 64>(limb2_bn);
		// decompose_big::<Fr, 4, 64>(limb3_bn);
		// let limb1_raw = Fr::from_raw([0x0, 0x10, 0x0, 0x0]);
		// let limb2_raw = Fr::from_raw([0x0, 0x0, 0x100, 0x0]);
		// let limb3_raw = Fr::from_raw([0x0, 0x0, 0x0, 0x1000]);
		// assert_eq!(limb1, limb1_raw);
		// assert_eq!(limb2, limb2_raw);
		// assert_eq!(limb3, limb3_raw);

		// let fr_mod = BigUint::from_str_radix(
		// 	"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
		// 	16,
		// )
		// .unwrap();
		// let fq_mod = BigUint::from_str_radix(
		// 	"30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
		// 	16,
		// )
		// .unwrap();
		// println!("{} {} {}", fq_mod.bits(), fr_mod.bits(), fq_mod - fr_mod);
	}
}
