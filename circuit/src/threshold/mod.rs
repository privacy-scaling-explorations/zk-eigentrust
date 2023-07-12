use halo2::{
	circuit::{SimpleFloorPlanner, Value},
	plonk::Circuit,
};

use crate::{
	gadgets::{
		bits2num::Bits2NumChip,
		lt_eq::{LessEqualConfig, NShiftedChip},
		main::{MainChip, MainConfig},
	},
	Chip, CommonConfig, FieldExt,
};

/// Native version of checking score threshold
pub mod native;

#[derive(Clone, Debug)]
/// The columns config for the Threshold circuit.
pub struct ThresholdCircuitConfig {
	common: CommonConfig,
	lt_eq: LessEqualConfig,
}

#[derive(Clone, Debug)]
/// Structure of the EigenTrustSet circuit
pub struct ThresholdCircuit<
	F: FieldExt,
	const NUM_LIMBS: usize,
	const POWER_OF_TEN: usize,
	const NUM_NEIGHBOURS: usize,
	const INITIAL_SCORE: u128,
> {
	score: Value<F>,
	num_decomposed: Vec<Value<F>>,
	den_decomposed: Vec<Value<F>>,
	threshold: Value<F>,
}

impl<
		F: FieldExt,
		const NUM_LIMBS: usize,
		const POWER_OF_TEN: usize,
		const NUM_NEIGHBOURS: usize,
		const INITIAL_SCORE: u128,
	> ThresholdCircuit<F, NUM_LIMBS, POWER_OF_TEN, NUM_NEIGHBOURS, INITIAL_SCORE>
{
	/// Constructs a new ThresholdCircuit
	pub fn new(score: F, num_decomposed: &[F], den_decomposed: &[F], threshold: F) -> Self {
		let score = Value::known(score);
		let num_decomposed =
			(0..NUM_LIMBS).map(|i| Value::known(num_decomposed[i].clone())).collect();
		let den_decomposed =
			(0..NUM_LIMBS).map(|i| Value::known(den_decomposed[i].clone())).collect();
		let threshold = Value::known(threshold);

		Self { score, num_decomposed, den_decomposed, threshold }
	}
}

impl<
		F: FieldExt,
		const NUM_LIMBS: usize,
		const POWER_OF_TEN: usize,
		const NUM_NEIGHBOURS: usize,
		const INITIAL_SCORE: u128,
	> Circuit<F> for ThresholdCircuit<F, NUM_LIMBS, POWER_OF_TEN, NUM_NEIGHBOURS, INITIAL_SCORE>
{
	type Config = ThresholdCircuitConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self {
			score: Value::unknown(),
			num_decomposed: (0..NUM_LIMBS).map(|_| Value::unknown()).collect(),
			den_decomposed: (0..NUM_LIMBS).map(|_| Value::unknown()).collect(),
			threshold: Value::unknown(),
		}
	}

	fn configure(meta: &mut halo2::plonk::ConstraintSystem<F>) -> Self::Config {
		let common = CommonConfig::new(meta);
		let main = MainConfig::new(MainChip::configure(&common, meta));

		let bits_2_num_selector = Bits2NumChip::configure(&common, meta);
		let n_shifted_selector = NShiftedChip::configure(&common, meta);
		let lt_eq = LessEqualConfig::new(main, bits_2_num_selector, n_shifted_selector);

		ThresholdCircuitConfig { common, lt_eq }
	}

	fn synthesize(
		&self, config: Self::Config, layouter: impl halo2::circuit::Layouter<F>,
	) -> Result<(), halo2::plonk::Error> {
		todo!()
	}
}
