use std::marker::PhantomData;

use halo2::{
	circuit::{AssignedCell, Layouter, Value},
	halo2curves::{group::ff::PrimeFieldBits, FieldExt},
	plonk::{Constraints, Expression, Selector},
	poly::Rotation,
};

use crate::{Chip, Chipset, RegionCtx};

/// Lookup short word check chip
#[derive(Debug, Clone)]
pub struct LookupShortWordCheckChip<F: FieldExt + PrimeFieldBits, const K: usize, const S: usize> {
	x: AssignedCell<F, F>,
}

impl<F: FieldExt + PrimeFieldBits, const K: usize, const S: usize>
	LookupShortWordCheckChip<F, K, S>
{
	/// Construct new instance
	pub fn new(x: AssignedCell<F, F>) -> Self {
		Self { x }
	}
}

impl<F: FieldExt + PrimeFieldBits, const K: usize, const S: usize> Chip<F>
	for LookupShortWordCheckChip<F, K, S>
{
	type Output = AssignedCell<F, F>;

	fn configure(
		common: &crate::CommonConfig, meta: &mut halo2::plonk::ConstraintSystem<F>,
	) -> Selector {
		assert!(0 < S && S < K, "Word bits should be less than target bits.");

		let q_bitshift = meta.complex_selector();

		let word_column = common.advice[0];

		meta.lookup("Check K bits limit", |meta| {
			let q_bit_shift = meta.query_selector(q_bitshift);
			let shifted_word = meta.query_advice(word_column, Rotation::cur());

			vec![(q_bit_shift * shifted_word, common.table)]
		});

		// For short lookups, check that the word has been shifted by the correct number
		// of bits. https://p.z.cash/halo2-0.1:decompose-short-lookup
		meta.create_gate("Short word S bits limit", |meta| {
			let q_bitshift = meta.query_selector(q_bitshift);
			let word = meta.query_advice(word_column, Rotation::prev());
			let shifted_word = meta.query_advice(word_column, Rotation::cur());
			let inv_two_pow_s = meta.query_advice(word_column, Rotation::next());

			let two_pow_k = F::from(1 << K);

			// shifted_word = word * 2^{K-s}
			//              = word * 2^K * inv_two_pow_s
			Constraints::with_selector(
				q_bitshift,
				Some(word * two_pow_k * inv_two_pow_s - shifted_word),
			)
		});

		q_bitshift
	}

	fn synthesize(
		self, common: &crate::CommonConfig, selector: &Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, halo2::plonk::Error> {
		layouter.assign_region(
			|| "check short word",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);

				// Assign original value
				let assigned_x = ctx.copy_assign(common.advice[0], self.x.clone())?;

				// Assign shifted value
				ctx.next();

				let shiftted_word = self.x.value().into_field() * F::from(1 << (K - S));
				ctx.assign_advice(common.advice[0], shiftted_word.evaluate())?;
				ctx.enable(selector.clone())?;

				// Assign 2^{-S} from a fixed column.
				ctx.next();

				let inv_two_pow_s = F::from(1 << S).invert().unwrap();
				ctx.assign_from_constant(common.advice[0], inv_two_pow_s)?;

				Ok(assigned_x)
			},
		)
	}
}

/// Lookup range check chip
#[derive(Debug, Clone)]
pub struct LookupRangeCheckChip<F: FieldExt + PrimeFieldBits, const K: usize, const N: usize> {
	x: AssignedCell<F, F>,
}
impl<F: FieldExt + PrimeFieldBits, const K: usize, const N: usize> Chip<F>
	for LookupRangeCheckChip<F, K, N>
{
	type Output = AssignedCell<F, F>;

	fn configure(
		common: &crate::CommonConfig, meta: &mut halo2::plonk::ConstraintSystem<F>,
	) -> Selector {
		todo!()
	}

	fn synthesize(
		self, common: &crate::CommonConfig, selector: &Selector, layouter: impl Layouter<F>,
	) -> Result<Self::Output, halo2::plonk::Error> {
		todo!()
	}
}

/// LookupRangeCheckChipsetConfig
#[derive(Debug, Clone)]
pub struct LookupRangeCheckChipsetConfig {
	q_running_sum: Selector,
	q_short_word: Selector,
}

/// LookupRangeCheckChipset
#[derive(Debug, Clone)]
pub struct LookupRangeCheckChipset<F: FieldExt + PrimeFieldBits, const K: usize> {
	x: AssignedCell<F, F>,
}

impl<F: FieldExt + PrimeFieldBits, const K: usize> LookupRangeCheckChipset<F, K> {
	/// Constructs new chipset
	pub fn new(x: AssignedCell<F, F>) -> Self {
		Self { x }
	}
}

impl<F: FieldExt + PrimeFieldBits, const K: usize> Chipset<F> for LookupRangeCheckChipset<F, K> {
	type Config = LookupRangeCheckChipsetConfig;
	type Output = AssignedCell<F, F>;

	// fn configure(
	// 	common: &crate::CommonConfig, meta: &mut halo2::plonk::ConstraintSystem<F>,
	// ) -> Selector {
	// 	let q_lookup = meta.complex_selector();
	// 	let q_running = meta.complex_selector();
	// 	let q_bitshift = meta.selector();

	// 	let running_sum = common.advice[0];

	// 	meta.lookup("running_sum check", |meta| {
	// 		let q_lookup = meta.query_selector(q_lookup);
	// 		let q_running = meta.query_selector(q_running);
	// 		let z_cur = meta.query_advice(running_sum, Rotation::cur());

	// 		// In the case of a running sum decomposition, we recover the word from
	// 		// the difference of the running sums:
	// 		//    z_i = 2^{K}⋅z_{i + 1} + a_i
	// 		// => a_i = z_i - 2^{K}⋅z_{i + 1}
	// 		let running_sum_lookup = {
	// 			let running_sum_word = {
	// 				let z_next = meta.query_advice(running_sum, Rotation::next());
	// 				z_cur.clone() - z_next * F::from(1 << K)
	// 			};

	// 			q_running.clone() * running_sum_word
	// 		};

	// 		// In the short range check, the word is directly witnessed.
	// 		let short_lookup = {
	// 			let short_word = z_cur;
	// 			let q_short = Expression::Constant(F::one()) - q_running;

	// 			q_short * short_word
	// 		};

	// 		// Combine the running sum and short lookups:
	// 		vec![(q_lookup * (running_sum_lookup + short_lookup), common.table)]
	// 	});

	// 	// For short lookups, check that the word has been shifted by the correct
	// number 	// of bits. https://p.z.cash/halo2-0.1:decompose-short-lookup
	// 	meta.create_gate("Short lookup bitshift", |meta| {
	// 		let q_bitshift = meta.query_selector(q_bitshift);
	// 		let word = meta.query_advice(running_sum, Rotation::prev());
	// 		let shifted_word = meta.query_advice(running_sum, Rotation::cur());
	// 		let inv_two_pow_s = meta.query_advice(running_sum, Rotation::next());

	// 		let two_pow_k = F::from(1 << K);

	// 		// shifted_word = word * 2^{K-s}
	// 		//              = word * 2^K * inv_two_pow_s
	// 		Constraints::with_selector(
	// 			q_bitshift,
	// 			Some(word * two_pow_k * inv_two_pow_s - shifted_word),
	// 		)
	// 	});

	// 	q_lookup
	// }

	fn synthesize(
		self, common: &crate::CommonConfig, config: &LookupRangeCheckChipsetConfig,
		mut layouter: impl halo2::circuit::Layouter<F>,
	) -> Result<Self::Output, halo2::plonk::Error> {
		todo!()
	}
}

#[cfg(test)]
mod tests {
	use crate::CommonConfig;

	use super::*;

	use halo2::{
		circuit::{Region, SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::pasta::Fp as Fr,
		plonk::{Circuit, ConstraintSystem, Error},
	};

	#[derive(Clone)]
	struct TestConfig {
		common: CommonConfig,
		q_bitshift: Selector,
	}

	#[derive(Clone)]
	struct TestCircuit {
		x: Fr,
	}

	impl TestCircuit {
		fn new(x: Fr) -> Self {
			Self { x }
		}
	}

	impl Circuit<Fr> for TestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			let common = CommonConfig::new(meta);
			let q_bitshift = LookupShortWordCheckChip::<Fr, 8, 3>::configure(&common, meta);

			TestConfig { common, q_bitshift }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			// Loads the values [0..2^K) into `common.table`.
			layouter.assign_table(
				|| "table_column",
				|mut table| {
					// We generate the row values lazily (we only need them during keygen).
					for index in 0..(1 << 8) {
						table.assign_cell(
							|| "table_column",
							config.common.table,
							index,
							|| Value::known(Fr::from(index as u64)),
						)?;
					}
					Ok(())
				},
			)?;

			let x = layouter.assign_region(
				|| "temp",
				|region: Region<'_, Fr>| {
					let mut ctx = RegionCtx::new(region, 0);
					let x_val = Value::known(self.x);
					let x = ctx.assign_advice(config.common.advice[0], x_val)?;
					Ok(x)
				},
			)?;

			let short_word_check_chip = LookupShortWordCheckChip::<Fr, 8, 3>::new(x);
			let _ = short_word_check_chip.synthesize(
				&config.common,
				&config.q_bitshift,
				layouter.namespace(|| "short word check"),
			)?;

			Ok(())
		}
	}

	#[test]
	fn test_short_word_case() {
		// Testing x is 3 bits
		let x = Fr::from(0b111);

		let test_chip = TestCircuit::new(x);

		let k = 9;
		let pub_ins = vec![];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		prover.assert_satisfied();

		// Should fail since x is 4 bits
		let x = Fr::from(0b1000);

		let test_chip = TestCircuit::new(x);

		let k = 4;
		let pub_ins = vec![];
		let _err = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap_err();
	}
}
