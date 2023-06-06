use crate::{
	rns::{compose_big_decimal_f, decompose_big_decimal},
	FieldExt,
};
use halo2::{arithmetic::Field, halo2curves::bn256::Fr};
use num_rational::BigRational;

/// Structure for threshold checks
pub struct Threshold<const NUM_LIMBS: usize, const POWER_OF_TEN: usize> {
	score: Fr,
	ratio: BigRational,
	threshold: Fr,
}

impl<const NUM_LIMBS: usize, const POWER_OF_TEN: usize> Threshold<NUM_LIMBS, POWER_OF_TEN> {
	/// Create new instance
	pub fn new(score: Fr, ratio: BigRational, threshold: Fr) -> Self {
		Self { score, ratio, threshold }
	}

	// TODO: Scale the ratio to the standardised decimal position
	// TODO: Find `NUM_LIMBS` and `POWER_OF_TEN` for standardised decimal position
	/// Method for checking the threshold for a given score
	pub fn check_threshold(&self) -> ThresholdWitness<Fr, NUM_LIMBS> {
		let Threshold { score, ratio, threshold } = self.clone();

		let x = ratio.clone();

		let num = x.numer();
		let den = x.denom();

		let num_decomposed =
			decompose_big_decimal::<Fr, NUM_LIMBS, POWER_OF_TEN>(num.to_biguint().unwrap());
		let den_decomposed =
			decompose_big_decimal::<Fr, NUM_LIMBS, POWER_OF_TEN>(den.to_biguint().unwrap());

		// Constraint checks - circuits should implement from this point
		let composed_num_f = compose_big_decimal_f::<Fr, NUM_LIMBS, POWER_OF_TEN>(num_decomposed);
		let composed_den_f = compose_big_decimal_f::<Fr, NUM_LIMBS, POWER_OF_TEN>(den_decomposed);
		let composed_den_f_inv = composed_den_f.invert().unwrap();
		let res_f = composed_num_f * composed_den_f_inv;
		assert!(res_f == *score);

		// Take the highest POWER_OF_TEN digits for comparison
		// This just means lower precision
		let first_limb_num = *num_decomposed.last().unwrap();
		let first_limb_den = *den_decomposed.last().unwrap();
		let comp = first_limb_den * threshold;
		let is_bigger = first_limb_num >= comp;

		ThresholdWitness { threshold: threshold.clone(), is_bigger, num_decomposed, den_decomposed }
	}
}

/// Witness structure for proving threshold checks
pub struct ThresholdWitness<F: FieldExt, const NUM_LIMBS: usize> {
	/// Threshold value to be checked with
	pub threshold: F,
	/// Comparison result
	pub is_bigger: bool,
	/// Target value numerator decomposition
	pub num_decomposed: [F; NUM_LIMBS],
	/// Target value denominator decomposition
	pub den_decomposed: [F; NUM_LIMBS],
}

#[cfg(test)]
mod tests {
	use halo2::halo2curves::ff::PrimeField;
	use itertools::Itertools;
	use num_bigint::{BigInt, ToBigInt};
	use num_rational::BigRational;
	use num_traits::{FromPrimitive, Zero};

	use super::*;
	use crate::{rns::compose_big_decimal, utils::fe_to_big};

	fn converge<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
	>(
		ops: &Vec<Vec<Fr>>,
	) -> Vec<Fr> {
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

		let mut s: Vec<Fr> =
			(0..NUM_NEIGHBOURS).into_iter().map(|_| Fr::from_u128(INITIAL_SCORE)).collect();
		let mut new_s: Vec<Fr> =
			(0..NUM_NEIGHBOURS).into_iter().map(|_| Fr::from_u128(INITIAL_SCORE)).collect();
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
		let sum_initial = Fr::from_u128(INITIAL_SCORE) * Fr::from_u128(NUM_NEIGHBOURS as u128);
		let sum_final = s.iter().fold(Fr::zero(), |acc, &score| acc + score);
		assert!(sum_initial == sum_final);

		s
	}

	fn converge_rational<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
	>(
		ops_fr: &Vec<Vec<Fr>>,
	) -> Vec<BigRational> {
		let mut ops = Vec::new();
		for i in 0..NUM_NEIGHBOURS {
			let ops_i = ops_fr[i].clone();
			let scores =
				ops_i.iter().map(|&score| fe_to_big(score).to_bigint().unwrap()).collect_vec();
			ops.push(scores);
		}

		let init_score_bn = BigInt::from_u128(INITIAL_SCORE).unwrap();
		let mut s: Vec<BigRational> =
			vec![BigRational::from_integer(init_score_bn); NUM_NEIGHBOURS];

		let mut ops_norm = vec![vec![BigRational::zero(); NUM_NEIGHBOURS]; NUM_NEIGHBOURS];
		for i in 0..NUM_NEIGHBOURS {
			let op_score_sum = ops[i].iter().fold(BigInt::zero(), |acc, score| acc + score);

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

	fn check_threshold_testing_helper<
		const NUM_NEIGHBOURS: usize,
		const NUM_ITERATIONS: usize,
		const INITIAL_SCORE: u128,
		const NUM_LIMBS: usize,
		const POWER_OF_TEN: usize,
	>(
		ops: Vec<Vec<Fr>>, threshold: Fr,
	) -> (
		Vec<Fr>,
		Vec<BigRational>,
		Vec<ThresholdWitness<Fr, NUM_LIMBS>>,
	) {
		assert!(ops.len() == NUM_NEIGHBOURS);
		for op in &ops {
			assert!(op.len() == NUM_NEIGHBOURS);
		}

		let s = converge::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&ops);
		let s_ratios = converge_rational::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(&ops);

		let mut tws = Vec::new();
		for (&score, ratio) in s.iter().zip(s_ratios.clone()) {
			let t: Threshold<NUM_LIMBS, POWER_OF_TEN> = Threshold::new(score, ratio, threshold);
			let tw = t.check_threshold();
			tws.push(tw);
		}

		(s, s_ratios, tws)
	}

	#[test]
	fn test_check_threshold_1() {
		const NUM_NEIGHBOURS: usize = 10;
		const NUM_ITERATIONS: usize = 30;
		const INITIAL_SCORE: u128 = 1000;
		// Constants related to threshold check
		const NUM_LIMBS: usize = 2;
		const POWER_OF_TEN: usize = 50;

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

		let threshold = 435;
		let (s, s_ratios, tws) = check_threshold_testing_helper::<
			NUM_NEIGHBOURS,
			NUM_ITERATIONS,
			INITIAL_SCORE,
			NUM_LIMBS,
			POWER_OF_TEN,
		>(ops, Fr::from_u128(threshold));

		let s_int: String = s_ratios.iter().map(|v| v.to_integer().to_str_radix(10)).join(", ");
		println!("NATIVE BIG_RATIONAL RESULT: [{}]", s_int);
		let s_formatted: Vec<String> = s.iter().map(|&x| fe_to_big(x).to_str_radix(10)).collect();
		println!("new s: {:#?}", s_formatted);
		for tw in tws {
			let num = compose_big_decimal::<Fr, NUM_LIMBS, POWER_OF_TEN>(tw.num_decomposed);
			let den = compose_big_decimal::<Fr, NUM_LIMBS, POWER_OF_TEN>(tw.den_decomposed);
			let ratio = BigRational::new(num.to_bigint().unwrap(), den.to_bigint().unwrap());
			println!(
				"real score: {:?}, is bigger than {}: {:?}",
				ratio.to_integer().to_str_radix(10),
				threshold,
				tw.is_bigger,
			);
		}
	}
}
