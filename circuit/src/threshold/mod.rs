use halo2::{
	circuit::{SimpleFloorPlanner, Value},
	plonk::{Circuit, Selector},
};

use crate::{
	gadgets::{
		bits2num::Bits2NumChip,
		lt_eq::{LessEqualChipset, LessEqualConfig, NShiftedChip},
		main::{InverseChipset, IsZeroChipset, MainChip, MainConfig, MulAddChipset, MulChipset},
		set::{SelectItemChip, SetPositionChip},
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
	set_pos_selector: Selector,
	select_item_selector: Selector,
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
		let num_decomposed = (0..NUM_LIMBS).map(|i| Value::known(num_decomposed[i])).collect();
		let den_decomposed = (0..NUM_LIMBS).map(|i| Value::known(den_decomposed[i])).collect();
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

		let set_pos_selector = SetPositionChip::configure(&common, meta);
		let select_item_selector = SelectItemChip::configure(&common, meta);

		ThresholdCircuitConfig { common, main, lt_eq, set_pos_selector, select_item_selector }
	}

	fn synthesize(
		&self, config: Self::Config, mut layouter: impl halo2::circuit::Layouter<F>,
	) -> Result<(), halo2::plonk::Error> {
		let (
			num_neighbor,
			init_score,
			max_limb_value,
			threshold,
			score,
			one,
			zero,
			sets_pk_x,
			sets_pk_y,
			final_scores,
			target_pk_x,
			target_pk_y,
			inst_col_offset,
		) = layouter.assign_region(
			|| "temp",
			|region| {
				let mut inst_col_offset = 0;
				let mut ctx = RegionCtx::new(region, 0);

				let num_neighbor = ctx.assign_from_constant(
					config.common.advice[0],
					F::from_u128(NUM_NEIGHBOURS as u128),
				)?;
				let init_score =
					ctx.assign_from_constant(config.common.advice[1], F::from_u128(INITIAL_SCORE))?;
				let max_limb_value = ctx.assign_from_constant(
					config.common.advice[2],
					F::from_u128(10_u128).pow([POWER_OF_TEN as u64]),
				)?;
				let threshold = ctx.assign_advice(config.common.advice[3], self.threshold)?;
				let score = ctx.assign_advice(config.common.advice[4], self.score)?;
				let one = ctx.assign_from_constant(config.common.advice[5], F::ONE)?;
				let zero = ctx.assign_from_constant(config.common.advice[6], F::ZERO)?;
				ctx.next();

				let mut sets_pk_x = vec![];
				for i in 0..NUM_NEIGHBOURS {
					let member = ctx.assign_from_instance(
						config.common.advice[i % ADVICE],
						config.common.instance,
						inst_col_offset + i,
					)?;
					sets_pk_x.push(member);

					if i % ADVICE == ADVICE - 1 {
						ctx.next();
					}
				}
				inst_col_offset += NUM_NEIGHBOURS;
				ctx.next();

				let mut sets_pk_y = vec![];
				for i in 0..NUM_NEIGHBOURS {
					let member = ctx.assign_from_instance(
						config.common.advice[i % ADVICE],
						config.common.instance,
						inst_col_offset + i,
					)?;
					sets_pk_y.push(member);

					if i % ADVICE == ADVICE - 1 {
						ctx.next();
					}
				}
				inst_col_offset += NUM_NEIGHBOURS;
				ctx.next();

				let mut final_scores = vec![];
				for i in 0..NUM_NEIGHBOURS {
					let score = ctx.assign_from_instance(
						config.common.advice[i % ADVICE],
						config.common.instance,
						inst_col_offset + i,
					)?;
					final_scores.push(score);

					if i % ADVICE == ADVICE - 1 {
						ctx.next();
					}
				}
				inst_col_offset += NUM_NEIGHBOURS;
				ctx.next();

				let target_pk_x = ctx.assign_from_instance(
					config.common.advice[0], config.common.instance, inst_col_offset,
				)?;
				let target_pk_y = ctx.assign_from_instance(
					config.common.advice[1],
					config.common.instance,
					inst_col_offset + 1,
				)?;
				inst_col_offset += 2;

				Ok((
					num_neighbor, init_score, max_limb_value, threshold, score, one, zero,
					sets_pk_x, sets_pk_y, final_scores, target_pk_x, target_pk_y, inst_col_offset,
				))
			},
		)?;

		// TODO: verify if the "sets" & "final_scores" are valid, using aggregation verify

		// check if the eigentrust score of "target_pk" is the same as "score"
		let set_pos_chip = SetPositionChip::new(sets_pk_x, target_pk_x);
		let target_pk_x_idx = set_pos_chip.synthesize(
			&config.common,
			&config.set_pos_selector,
			layouter.namespace(|| "target_pk_x_idx"),
		)?;
		let set_pos_chip = SetPositionChip::new(sets_pk_y, target_pk_y);
		let target_pk_y_idx = set_pos_chip.synthesize(
			&config.common,
			&config.set_pos_selector,
			layouter.namespace(|| "target_pk_y_idx"),
		)?;
		layouter.assign_region(
			|| "target_pk_x_idx == target_pk_y_idx",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				let x_idx = ctx.copy_assign(config.common.advice[0], target_pk_x_idx.clone())?;
				let y_idx = ctx.copy_assign(config.common.advice[1], target_pk_y_idx.clone())?;
				ctx.constrain_equal(x_idx, y_idx)?;
				Ok(())
			},
		)?;

		let select_item_chip = SelectItemChip::new(final_scores, target_pk_x_idx);
		let target_pk_score = select_item_chip.synthesize(
			&config.common,
			&config.select_item_selector,
			layouter.namespace(|| "select score from final_scores"),
		)?;
		layouter.assign_region(
			|| "target_pk_score(PI) == score(input)",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				let target_pk_score =
					ctx.copy_assign(config.common.advice[0], target_pk_score.clone())?;
				let input_score = ctx.copy_assign(config.common.advice[1], score.clone())?;
				ctx.constrain_equal(target_pk_score, input_score)?;
				Ok(())
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
				let res = ctx.copy_assign(config.common.advice[0], res.clone())?;
				let one = ctx.copy_assign(config.common.advice[1], one.clone())?;
				ctx.constrain_equal(res, one)?;

				Ok(())
			},
		)?;

		// check every element of "num_decomposed"
		let num_decomposed_limbs = layouter.assign_region(
			|| "num_decomposed",
			|region| {
				let mut limbs = vec![];

				let mut ctx = RegionCtx::new(region, 0);
				for i in 0..self.num_decomposed.len() {
					let limb = ctx
						.assign_advice(config.common.advice[i % ADVICE], self.num_decomposed[i])?;
					limbs.push(limb);

					if i % ADVICE == ADVICE - 1 {
						ctx.next();
					}
				}

				Ok(limbs)
			},
		)?;

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
					let res = ctx.copy_assign(config.common.advice[0], res.clone())?;
					let one = ctx.copy_assign(config.common.advice[1], one.clone())?;
					ctx.constrain_equal(res, one)?;

					Ok(())
				},
			)?;
		}

		// check every element of "den_decomposed"
		let den_decomposed_limbs = layouter.assign_region(
			|| "den_decomposed",
			|region| {
				let mut limbs = vec![];

				let mut ctx = RegionCtx::new(region, 0);
				for i in 0..self.den_decomposed.len() {
					let limb = ctx
						.assign_advice(config.common.advice[i % ADVICE], self.den_decomposed[i])?;
					limbs.push(limb);

					if i % ADVICE == ADVICE - 1 {
						ctx.next();
					}
				}
				Ok(limbs)
			},
		)?;

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
					let res = ctx.copy_assign(config.common.advice[0], res.clone())?;
					let one = ctx.copy_assign(config.common.advice[1], one.clone())?;
					ctx.constrain_equal(res, one)?;

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
			inv_chipset.synthesize(
				&config.common,
				&config.main,
				layouter.namespace(|| "composed_den ^ -1"),
			)?
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
				let res = ctx.copy_assign(config.common.advice[0], res.clone())?;
				let score = ctx.copy_assign(config.common.advice[1], score.clone())?;
				ctx.constrain_equal(res, score)?;

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
				let res = ctx.copy_assign(config.common.advice[0], res.clone())?;
				let zero = ctx.copy_assign(config.common.advice[1], zero.clone())?;
				ctx.constrain_equal(res, zero)?;

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
		let threshold_check_res = lt_eq_chipset.synthesize(
			&config.common,
			&config.lt_eq,
			layouter.namespace(|| "comp <= last_limb_num"),
		)?;

		// final constraint
		layouter.constrain_instance(
			threshold_check_res.cell(),
			config.common.instance,
			inst_col_offset,
		)?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::{
		calculate_message_hash,
		dynamic_sets::native::{EigenTrustSet, Opinion},
		eddsa::native::{sign, PublicKey, SecretKey},
		params::rns::decompose_big_decimal,
		threshold::native::Threshold,
	};
	use halo2::{
		arithmetic::Field,
		dev::MockProver,
		halo2curves::{bn256::Fr, ff::PrimeField},
	};
	use num_bigint::BigInt;
	use num_rational::BigRational;
	use rand::thread_rng;

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
	) -> (Vec<PublicKey>, Vec<Fr>, Vec<BigRational>) {
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

		(pks, s, s_ratios)
	}

	fn ratio_to_decomposed_helper<
		F: FieldExt,
		const NUM_LIMBS: usize,
		const POWER_OF_TEN: usize,
	>(
		ratio: BigRational,
	) -> ([F; NUM_LIMBS], [F; NUM_LIMBS]) {
		let num = ratio.numer();
		let den = ratio.denom();
		let max_len = NUM_LIMBS * POWER_OF_TEN;
		let bigger = num.max(den);
		let dig_len = bigger.to_string().len();
		let diff = max_len - dig_len;

		let scale = BigInt::from(10_u32).pow(diff as u32);
		let num_scaled = num * scale.clone();
		let den_scaled = den * scale;
		let num_scaled_uint = num_scaled.to_biguint().unwrap();
		let den_scaled_uint = den_scaled.to_biguint().unwrap();

		let num_decomposed = decompose_big_decimal::<F, NUM_LIMBS, POWER_OF_TEN>(num_scaled_uint);
		let den_decomposed = decompose_big_decimal::<F, NUM_LIMBS, POWER_OF_TEN>(den_scaled_uint);

		(num_decomposed, den_decomposed)
	}

	#[test]
	fn test_threshold_circuit() {
		const NUM_NEIGHBOURS: usize = 4;
		const NUM_ITERATIONS: usize = 20;
		const INITIAL_SCORE: u128 = 1000;

		const NUM_LIMBS: usize = 2;
		const POWER_OF_TEN: usize = 72;

		let ops: Vec<Vec<Fr>> = vec![
			vec![0, 200, 300, 500],
			vec![100, 0, 600, 300],
			vec![400, 100, 0, 500],
			vec![100, 200, 700, 0],
		]
		.into_iter()
		.map(|arr| arr.into_iter().map(|x| Fr::from_u128(x)).collect())
		.collect();

		let (pks, final_scores, score_ratios) =
			eigen_trust_set_testing_helper::<NUM_NEIGHBOURS, NUM_ITERATIONS, INITIAL_SCORE>(ops);

		let target_idx = 2;

		let score = final_scores[target_idx].clone();
		let score_ratio = score_ratios[target_idx].clone();
		let (num_decomposed, den_decomposed) =
			ratio_to_decomposed_helper::<Fr, NUM_LIMBS, POWER_OF_TEN>(score_ratio.clone());
		let threshold = Fr::from_u128(1000_u128);

		let native_threshold: Threshold<
			Fr,
			NUM_LIMBS,
			POWER_OF_TEN,
			NUM_NEIGHBOURS,
			INITIAL_SCORE,
		> = Threshold::new(score, score_ratio, threshold);

		let threshold_circuit: ThresholdCircuit<
			Fr,
			NUM_LIMBS,
			POWER_OF_TEN,
			NUM_NEIGHBOURS,
			INITIAL_SCORE,
		> = ThresholdCircuit::new(score, &num_decomposed, &den_decomposed, threshold);

		let mut pub_ins = vec![];
		let sets_pk_x: Vec<Fr> = pks.iter().map(|pk| pk.0.x.clone()).collect();
		let sets_pk_y: Vec<Fr> = pks.iter().map(|pk| pk.0.y.clone()).collect();
		let target_pk_x = sets_pk_x[target_idx].clone();
		let target_pk_y = sets_pk_y[target_idx].clone();
		let threshold_check_res =
			if native_threshold.check_threshold() { Fr::ONE } else { Fr::ZERO };
		pub_ins.extend(sets_pk_x);
		pub_ins.extend(sets_pk_y);
		pub_ins.extend(final_scores.clone());
		pub_ins.push(target_pk_x);
		pub_ins.push(target_pk_y);
		pub_ins.push(threshold_check_res);

		let k = 12;
		let prover = match MockProver::<Fr>::run(k, &threshold_circuit, vec![pub_ins]) {
			Ok(prover) => prover,
			Err(e) => panic!("{}", e),
		};

		assert_eq!(prover.verify(), Ok(()));
	}
}
