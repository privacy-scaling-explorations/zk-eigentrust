use halo2::{
	circuit::{SimpleFloorPlanner, Value},
	plonk::Circuit,
};

use crate::{
	gadgets::{
		bits2num::Bits2NumChip,
		lt_eq::{LessEqualChipset, LessEqualConfig, NShiftedChip},
		main::{InverseChipset, IsZeroChipset, MainChip, MainConfig, MulAddChipset, MulChipset},
	},
	Chip, Chipset, CommonConfig, FieldExt, RegionCtx, ADVICE,
};

/// Native version of checking score threshold
pub mod native;

#[derive(Clone, Debug)]
/// The columns config for the Threshold circuit.
pub struct ThresholdCircuitConfig {
	common: CommonConfig,
	main: MainConfig,
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
		let lt_eq = LessEqualConfig::new(main.clone(), bits_2_num_selector, n_shifted_selector);

		ThresholdCircuitConfig { common, main, lt_eq }
	}

	fn synthesize(
		&self, config: Self::Config, mut layouter: impl halo2::circuit::Layouter<F>,
	) -> Result<(), halo2::plonk::Error> {
		let (num_neighbor, init_score, max_limb_value, threshold, score, one, zero) = layouter
			.assign_region(
				|| "temp",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);

					let num_neighbor = ctx.assign_from_constant(
						config.common.advice[0],
						F::from_u128(NUM_NEIGHBOURS as u128),
					)?;
					let init_score = ctx.assign_from_constant(
						config.common.advice[1],
						F::from_u128(INITIAL_SCORE as u128),
					)?;
					let max_limb_value = ctx.assign_from_constant(
						config.common.advice[2],
						F::from_u128(10_u128).pow([POWER_OF_TEN as u64]),
					)?;
					let threshold = ctx.assign_advice(config.common.advice[3], self.threshold)?;
					let score = ctx.assign_advice(config.common.advice[4], self.score)?;
					let one = ctx.assign_from_constant(config.common.advice[5], F::ONE)?;
					let zero = ctx.assign_from_constant(config.common.advice[6], F::ZERO)?;

					Ok((
						num_neighbor, init_score, max_limb_value, threshold, score, one, zero,
					))
				},
			)?;

		// max_score = NUM_NEIGHBOURS * INITIAL_SCORE
		let max_score = {
			let mul_chipset = MulChipset::new(num_neighbor, init_score);
			mul_chipset.synthesize(
				&config.common,
				&config.main,
				layouter.namespace(|| "NUM_NEIGHBOURS * INITIAL_SCORE"),
			)?
		};

		// assert!(threshold < max_score)
		let lt_eq_chipset = LessEqualChipset::new(threshold.clone(), max_score);
		let res = lt_eq_chipset.synthesize(
			&config.common,
			&config.lt_eq,
			layouter.namespace(|| "threshold < max_score"),
		)?;
		layouter.assign_region(
			|| "res == 1",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				ctx.constrain_equal(res.clone(), one.clone())?;

				Ok(())
			},
		)?;

		// check every element of "num_decomposed"
		let num_decomposed_limbs = {
			let mut limbs = vec![];
			layouter.assign_region(
				|| "num_decomposed",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					for i in 0..self.num_decomposed.len() {
						let limb = ctx.assign_advice(
							config.common.advice[i % ADVICE],
							self.num_decomposed[i],
						)?;
						limbs.push(limb);

						if i % ADVICE == ADVICE - 1 {
							ctx.next();
						}
					}
					Ok(())
				},
			)?;
			limbs
		};

		for i in 0..num_decomposed_limbs.len() {
			// assert!(limb < max_limb_value)
			let lt_eq_chipset =
				LessEqualChipset::new(num_decomposed_limbs[i].clone(), max_limb_value.clone());
			let res = lt_eq_chipset.synthesize(
				&config.common,
				&config.lt_eq,
				layouter.namespace(|| "(num_decomposed) limb < max_limb_value"),
			)?;
			layouter.assign_region(
				|| "res == 1",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					ctx.constrain_equal(res.clone(), one.clone())?;

					Ok(())
				},
			)?;
		}

		// check every element of "den_decomposed"
		let den_decomposed_limbs = {
			let mut limbs = vec![];
			layouter.assign_region(
				|| "den_decomposed",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					for i in 0..self.den_decomposed.len() {
						let limb = ctx.assign_advice(
							config.common.advice[i % ADVICE],
							self.den_decomposed[i],
						)?;
						limbs.push(limb);

						if i % ADVICE == ADVICE - 1 {
							ctx.next();
						}
					}
					Ok(())
				},
			)?;
			limbs
		};

		for i in 0..den_decomposed_limbs.len() {
			// assert!(limb < max_limb_value)
			let lt_eq_chipset =
				LessEqualChipset::new(den_decomposed_limbs[i].clone(), max_limb_value.clone());
			let res = lt_eq_chipset.synthesize(
				&config.common,
				&config.lt_eq,
				layouter.namespace(|| "(den_decomposed) limb < max_limb_value"),
			)?;
			layouter.assign_region(
				|| "res == 1",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					ctx.constrain_equal(res.clone(), one.clone())?;

					Ok(())
				},
			)?;
		}

		// composed_num * composed_den_inv == score
		let composed_num = {
			let mut limbs = num_decomposed_limbs.clone();
			limbs.reverse();
			let scale = max_limb_value.clone();

			let mut val = limbs[0].clone();
			for limb in limbs.iter().take(NUM_LIMBS).skip(1) {
				let mul_add_chipset = MulAddChipset::new(val, scale.clone(), limb.clone());
				val = mul_add_chipset.synthesize(
					&config.common,
					&config.main,
					layouter.namespace(|| "val * scale + limb"),
				)?;
			}

			val
		};

		let composed_den = {
			let mut limbs = den_decomposed_limbs.clone();
			limbs.reverse();
			let scale = max_limb_value;

			let mut val = limbs[0].clone();
			for limb in limbs.iter().take(NUM_LIMBS).skip(1) {
				let mul_add_chipset = MulAddChipset::new(val, scale.clone(), limb.clone());
				val = mul_add_chipset.synthesize(
					&config.common,
					&config.main,
					layouter.namespace(|| "val * scale + limb"),
				)?;
			}

			val
		};

		let composed_den_inv = {
			let inv_chipset = InverseChipset::new(composed_den);
			let res = inv_chipset.synthesize(
				&config.common,
				&config.main,
				layouter.namespace(|| "composed_den ^ -1"),
			)?;
			res
		};

		let mul_chipset = MulChipset::new(composed_num, composed_den_inv);
		let res = mul_chipset.synthesize(
			&config.common,
			&config.main,
			layouter.namespace(|| "composed_num * composed_den_inv"),
		)?;
		layouter.assign_region(
			|| "res == score",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				ctx.constrain_equal(res.clone(), score.clone())?;

				Ok(())
			},
		)?;

		// Take the highest POWER_OF_TEN digits for comparison
		// This just means lower precision
		let last_limb_num = num_decomposed_limbs.last().unwrap();
		let last_limb_den = den_decomposed_limbs.last().unwrap();

		// assert!(last_limb_den != 0)
		let is_zero_chipset = IsZeroChipset::new(last_limb_den.clone());
		let res = is_zero_chipset.synthesize(
			&config.common,
			&config.main,
			layouter.namespace(|| "last_limb_den != 0"),
		)?;
		layouter.assign_region(
			|| "res == 0",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				ctx.constrain_equal(res.clone(), zero.clone())?;

				Ok(())
			},
		)?;

		let mul_chipset = MulChipset::new(last_limb_den.clone(), threshold);
		let comp = mul_chipset.synthesize(
			&config.common,
			&config.main,
			layouter.namespace(|| "last_limb_den * threshold"),
		)?;

		let lt_eq_chipset = LessEqualChipset::new(comp, last_limb_num.clone());
		let res = lt_eq_chipset.synthesize(
			&config.common,
			&config.lt_eq,
			layouter.namespace(|| "comp <= last_limb_num"),
		)?;

		// Todo: really?
		layouter.constrain_instance(res.cell(), config.common.instance, 0)?;

		Ok(())
	}
}
