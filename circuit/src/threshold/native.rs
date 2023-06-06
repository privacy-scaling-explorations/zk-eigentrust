use crate::{
	rns::{compose_big_decimal_f, decompose_big_decimal},
	FieldExt,
};
use num_rational::BigRational;

/// Structure for threshold checks
pub struct Threshold<F: FieldExt + PartialOrd, const NUM_LIMBS: usize, const POWER_OF_TEN: usize> {
	score: F,
	ratio: BigRational,
	threshold: F,
}

impl<F: FieldExt + PartialOrd, const NUM_LIMBS: usize, const POWER_OF_TEN: usize>
	Threshold<F, NUM_LIMBS, POWER_OF_TEN>
{
	/// Create new instance
	pub fn new(score: F, ratio: BigRational, threshold: F) -> Self {
		Self { score, ratio, threshold }
	}

	// TODO: Scale the ratio to the standardised decimal position
	// TODO: Find `NUM_LIMBS` and `POWER_OF_TEN` for standardised decimal position
	/// Method for checking the threshold for a given score
	pub fn check_threshold(&self) -> ThresholdWitness<F, NUM_LIMBS> {
		let Threshold { score, ratio, threshold } = self.clone();

		let x = ratio.clone();

		let num = x.numer();
		let den = x.denom();

		let num_decomposed =
			decompose_big_decimal::<F, NUM_LIMBS, POWER_OF_TEN>(num.to_biguint().unwrap());
		let den_decomposed =
			decompose_big_decimal::<F, NUM_LIMBS, POWER_OF_TEN>(den.to_biguint().unwrap());

		// Constraint checks - circuits should implement from this point
		let composed_num_f = compose_big_decimal_f::<F, NUM_LIMBS, POWER_OF_TEN>(num_decomposed);
		let composed_den_f = compose_big_decimal_f::<F, NUM_LIMBS, POWER_OF_TEN>(den_decomposed);
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
