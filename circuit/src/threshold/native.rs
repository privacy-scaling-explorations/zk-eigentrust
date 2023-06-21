use crate::{
	params::rns::{compose_big_decimal_f, decompose_big_decimal},
	utils::fe_to_big,
	FieldExt,
};
use num_bigint::{BigInt, BigUint};
use num_rational::BigRational;
use num_traits::{One, Zero};

/// Structure for threshold checks
pub struct Threshold<F: FieldExt, const NUM_LIMBS: usize, const POWER_OF_TEN: usize> {
	score: F,
	num_decomposed: [F; NUM_LIMBS],
	den_decomposed: [F; NUM_LIMBS],
	threshold: F,
}

impl<F: FieldExt, const NUM_LIMBS: usize, const POWER_OF_TEN: usize>
	Threshold<F, NUM_LIMBS, POWER_OF_TEN>
{
	/// Create new instance
	pub fn new(score: F, ratio: BigRational, threshold: F) -> Self {
		let num = ratio.numer();
		let den = ratio.denom();
		let max_len = NUM_LIMBS * POWER_OF_TEN;
		let bigger = num.max(den);
		let dig_len = bigger.to_string().len();
		let diff = max_len - dig_len;
		assert!(diff < POWER_OF_TEN);

		let scale = BigInt::from(10_u32).pow(diff as u32);
		let num_scaled = num * scale.clone();
		let den_scaled = den * scale;
		let num_scaled_uint = num_scaled.to_biguint().unwrap();
		let den_scaled_uint = den_scaled.to_biguint().unwrap();

		let num_decomposed = decompose_big_decimal::<F, NUM_LIMBS, POWER_OF_TEN>(num_scaled_uint);
		let den_decomposed = decompose_big_decimal::<F, NUM_LIMBS, POWER_OF_TEN>(den_scaled_uint);
		Self { score, num_decomposed, den_decomposed, threshold }
	}

	/// Method for checking the threshold for a given score
	// Constraint checks - circuits should implement from this point
	pub fn check_threshold<const NUM_NEIGHBOURS: usize, const INITIAL_SCORE: usize>(&self) -> bool {
		let threshold_bn = fe_to_big(self.threshold);
		let max_score_bn = BigUint::from(NUM_NEIGHBOURS * INITIAL_SCORE);
		assert!(threshold_bn <= max_score_bn);

		let composed_num_f =
			compose_big_decimal_f::<F, NUM_LIMBS, POWER_OF_TEN>(self.num_decomposed);
		let composed_den_f =
			compose_big_decimal_f::<F, NUM_LIMBS, POWER_OF_TEN>(self.den_decomposed);
		let composed_den_f_inv = composed_den_f.invert().unwrap();
		let res_f = composed_num_f * composed_den_f_inv;
		assert!(res_f == self.score);

		// Take the highest POWER_OF_TEN digits for comparison
		// This just means lower precision
		let last_limb_num = *self.num_decomposed.last().unwrap();
		let last_limb_den = *self.den_decomposed.last().unwrap();
		let last_limb_num_bn = fe_to_big(last_limb_num);
		let last_limb_den_bn = fe_to_big(last_limb_den);

		let max_limb_value_bn =
			BigUint::from(10u32).pow((POWER_OF_TEN + 1) as u32) - BigUint::one();
		let max_f_bn = fe_to_big(F::ZERO - F::ONE);
		assert!(max_score_bn * max_limb_value_bn < max_f_bn);
		assert!(!last_limb_den_bn.is_zero());

		let comp = last_limb_den * self.threshold;
		let comp_bn = fe_to_big(comp);

		let is_bigger = last_limb_num_bn >= comp_bn;

		is_bigger
	}
}

#[cfg(test)]
mod tests {
	use halo2::{
		arithmetic::Field,
		halo2curves::{bn256::Fr, ff::PrimeField},
	};
	use num_bigint::BigInt;
	use num_rational::BigRational;
	use num_traits::FromPrimitive;
	use rand::{thread_rng, Rng};

	use crate::{
		calculate_message_hash,
		dynamic_sets::native::{EigenTrustSet, Opinion},
		eddsa::native::{sign, PublicKey, SecretKey},
	};

	use super::*;

	#[test]
	fn test_check_threshold_1() {
		const NUM_LIMBS: usize = 2;
		const POWER_OF_TEN: usize = 3;

		let threshold = 346;
		let num = 345111;
		let den = 1000;

		let comp_u128 = num >= den * threshold;
		println!("comp_u128: {:?}", comp_u128);

		let num_bn = BigInt::from_u128(num).unwrap();
		let den_bn = BigInt::from_u128(den).unwrap();

		let threshold_fr = Fr::from_u128(threshold);
		let num_fr = Fr::from_u128(num);
		let den_fr = Fr::from_u128(den);

		let score = num_fr * den_fr.invert().unwrap();

		let ratio = BigRational::new(num_bn, den_bn);
		let t: Threshold<Fr, NUM_LIMBS, POWER_OF_TEN> = Threshold::new(score, ratio, threshold_fr);
		let is_bigger = t.check_threshold::<4, 1000>();

		assert!(!is_bigger);
	}

	#[test]
	fn test_check_threshold_2() {
		const NUM_LIMBS: usize = 2;
		const POWER_OF_TEN: usize = 3;

		let threshold = 344;
		let num = 345111;
		let den = 1000;

		let comp_u128 = num >= den * threshold;
		println!("comp_u128: {:?}", comp_u128);

		let num_bn = BigInt::from_u128(num).unwrap();
		let den_bn = BigInt::from_u128(den).unwrap();

		let threshold_fr = Fr::from_u128(threshold);
		let num_fr = Fr::from_u128(num);
		let den_fr = Fr::from_u128(den);

		let score = num_fr * den_fr.invert().unwrap();

		let ratio = BigRational::new(num_bn, den_bn);
		let t: Threshold<Fr, NUM_LIMBS, POWER_OF_TEN> = Threshold::new(score, ratio, threshold_fr);
		let is_bigger = t.check_threshold::<4, 1000>();

		assert!(is_bigger);
	}

	#[test]
	fn test_check_threshold_3() {
		const NUM_LIMBS: usize = 5;
		const POWER_OF_TEN: usize = 3;

		let threshold = 346;
		let num = 347123456789123;
		let den = 1984263563965;

		let comp_u128 = num >= den * threshold;
		println!("comp_u128: {:?}", comp_u128);

		let num_bn = BigInt::from_u128(num).unwrap();
		let den_bn = BigInt::from_u128(den).unwrap();

		let threshold_fr = Fr::from_u128(threshold);
		let num_fr = Fr::from_u128(num);
		let den_fr = Fr::from_u128(den);

		let score = num_fr * den_fr.invert().unwrap();

		let ratio = BigRational::new(num_bn, den_bn);
		let t: Threshold<Fr, NUM_LIMBS, POWER_OF_TEN> = Threshold::new(score, ratio, threshold_fr);
		let is_bigger = t.check_threshold::<4, 1000>();

		assert!(is_bigger);
	}

	fn sign_opinion<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
	>(
		sk: &SecretKey, pk: &PublicKey, pks: &[PublicKey], scores: &[Fr],
	) -> Opinion<NUM_NEIGHBOURS> {
		assert!(pks.len() == NUM_NEIGHBOURS);
		assert!(scores.len() == NUM_NEIGHBOURS);

		let (_, message_hashes) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(pks.to_vec(), vec![scores.to_vec()]);
		let sig = sign(sk, pk, message_hashes[0]);

		// let scores = pks.zip(*scores);
		let mut op_scores = vec![];
		for i in 0..NUM_NEIGHBOURS {
			op_scores.push((pks[i], scores[i]));
		}
		let op = Opinion::new(sig, message_hashes[0], op_scores.to_vec());
		op
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

		let mut set = EigenTrustSet::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>::new();

		let rng = &mut thread_rng();

		let sks: Vec<SecretKey> =
			(0..NUM_NEIGHBOURS).into_iter().map(|__| SecretKey::random(rng)).collect();
		let pks: Vec<PublicKey> = sks.iter().map(|s| s.public()).collect();

		// Add the publicKey to the set
		pks.iter().for_each(|pk| set.add_member(*pk));

		// Update the opinions
		for i in 0..NUM_NEIGHBOURS {
			let scores = ops[i].to_vec();

			let op_i = sign_opinion::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
				&sks[i], &pks[i], &pks, &scores,
			);

			set.update_op(pks[i], op_i);
		}

		let s = set.converge();
		let s_ratios = set.converge_rational();

		(s, s_ratios)
	}

	// #[ignore = "Scaling test takes too long to run"]
	#[test]
	fn test_scaling_4_peers() {
		const NUM_NEIGHBOURS: usize = 4;
		const NUM_ITERATIONS: usize = 20;
		const INITIAL_SCORE: u128 = 1000;

		let rng = &mut thread_rng();
		let mut biggest = 0;
		for _ in 0..1000 {
			let mut ops_raw = [(); NUM_NEIGHBOURS].map(|_| [(); NUM_NEIGHBOURS].map(|_| 0));
			for i in 0..NUM_NEIGHBOURS {
				ops_raw[i] = rng.gen::<[u8; NUM_NEIGHBOURS]>();
			}

			let ops = ops_raw.map(|arr| arr.map(|x| Fr::from_u128(x as u128)).to_vec()).to_vec();

			let (_, s_ratios) =
				eigen_trust_set_testing_helper::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(
					ops,
				);

			for ratio in s_ratios {
				let num_len = ratio.numer().to_string().len();
				let den_len = ratio.denom().to_string().len();
				println!("num_len: {:?}, den_len: {:?}", num_len, den_len);
				let curr = num_len.max(den_len);
				if curr > biggest {
					biggest = curr;
				}
			}
		}

		println!("{:?}", biggest);
	}

	#[test]
	fn test_4_peer_consts() {
		// const THRESHOLD: u128 = 1000;
		// const NUM_LIMBS: usize = 3;
		// const POWER_OF_TEN: usize = 40;

		// let threshold = Fr::from_u128(THRESHOLD);
		// let mut tws = Vec::new();
		// for (&score, ratio) in s.iter().zip(s_ratios.clone()) {
		// 	let t: Threshold<NUM_LIMBS, POWER_OF_TEN> = Threshold::new(score, ratio, threshold);
		// 	let tw = t.check_threshold();
		// 	tws.push(tw);
		// }

		// let s_int: String = s_ratios.iter().map(|v| v.to_integer().to_str_radix(10)).join(", ");
		// println!("NATIVE BIG_RATIONAL RESULT: [{}]", s_int);
		// for tw in tws {
		// 	let num = compose_big_decimal::<Fr, NUM_LIMBS, POWER_OF_TEN>(tw.num_decomposed);
		// 	let den = compose_big_decimal::<Fr, NUM_LIMBS, POWER_OF_TEN>(tw.den_decomposed);
		// 	let ratio = BigRational::new(num.to_bigint().unwrap(), den.to_bigint().unwrap());
		// 	let ratio_prime = ratio.to_integer().to_str_radix(10).parse::<u128>().unwrap();
		// 	let is_bigger = ratio_prime >= THRESHOLD;
		// 	if is_bigger != tw.is_bigger {
		// 		println!(
		// 			"real score: {:?}, is bigger than {}: {:?}",
		// 			ratio.to_integer().to_str_radix(10),
		// 			THRESHOLD,
		// 			tw.is_bigger,
		// 		);
		// 		return false;
		// 	}
		// }
	}
}
