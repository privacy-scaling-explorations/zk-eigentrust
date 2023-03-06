use std::marker::PhantomData;

use halo2::{
	circuit::{AssignedCell, Layouter, Value},
	halo2curves::{group::ff::PrimeFieldBits, FieldExt},
	plonk::{Constraints, Expression, Selector},
	poly::Rotation,
};

use crate::{utils::lebs2ip, Chip, Chipset, RegionCtx};

// Check 252 bit number
const K: usize = 8;
const N: usize = 32;
const S: usize = 4;

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

				let shifted_word = self.x.value().cloned() * Value::known(F::from(1 << (K - S)));
				ctx.assign_advice(common.advice[0], shifted_word)?;
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

impl<F: FieldExt + PrimeFieldBits, const K: usize, const N: usize> LookupRangeCheckChip<F, K, N> {
	/// Construct a new instance
	pub fn new(x: AssignedCell<F, F>) -> Self {
		Self { x }
	}
}

impl<F: FieldExt + PrimeFieldBits, const K: usize, const N: usize> Chip<F>
	for LookupRangeCheckChip<F, K, N>
{
	type Output = AssignedCell<F, F>;

	fn configure(
		common: &crate::CommonConfig, meta: &mut halo2::plonk::ConstraintSystem<F>,
	) -> Selector {
		let q_running = meta.complex_selector();

		let running_sum = common.advice[0];

		meta.lookup("running_sum check", |meta| {
			let q_running = meta.query_selector(q_running);
			let z_cur = meta.query_advice(running_sum, Rotation::cur());

			// In the case of a running sum decomposition, we recover the word from
			// the difference of the running sums:
			//    z_i = 2^{K}⋅z_{i + 1} + a_i
			// => a_i = z_i - 2^{K}⋅z_{i + 1}
			let running_sum_lookup = {
				let running_sum_word = {
					let z_next = meta.query_advice(running_sum, Rotation::next());
					z_cur.clone() - z_next * F::from(1 << K)
				};

				q_running.clone() * running_sum_word
			};

			// Combine the running sum and short lookups:
			vec![(running_sum_lookup, common.table)]
		});

		q_running
	}

	fn synthesize(
		self, common: &crate::CommonConfig, selector: &Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, halo2::plonk::Error> {
		layouter.assign_region(
			|| "range check",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				let x = ctx.copy_assign(common.advice[0], self.x.clone())?;

				let num_bits = K * N;

				// Chunk the first num_bits bits into K-bit words.
				let words = {
					// Take first num_bits bits of `element`.
					let bits = self.x.value().map(|element| {
						element.to_le_bits().into_iter().take(num_bits).collect::<Vec<_>>()
					});

					bits.map(|bits| {
						bits.chunks_exact(K)
							.map(|word| F::from(lebs2ip::<K>(&(word.try_into().unwrap()))))
							.collect::<Vec<_>>()
					})
					.transpose_vec(N)
				};

				let mut zs = vec![x.clone()];

				// Assign cumulative sum such that
				//          z_i = 2^{K}⋅z_{i + 1} + a_i
				// => z_{i + 1} = (z_i - a_i) / (2^K)
				//
				// For `element` = a_0 + 2^10 a_1 + ... + 2^{120} a_{12}}, initialize z_0 =
				// `element`. If `element` fits in 130 bits, we end up with z_{13} = 0.
				let mut z = x.clone();
				let inv_two_pow_k = F::from(1u64 << K).invert().unwrap();
				for word in words {
					// Enable q_lookup on this row
					ctx.enable(selector.clone())?;

					// z_next = (z_cur - m_cur) / 2^K
					z = {
						let z_val =
							z.value().zip(word).map(|(z, word)| (*z - word) * inv_two_pow_k);

						// Assign z_next
						ctx.next();
						ctx.assign_advice(common.advice[0], z_val)?
					};

					zs.push(z.clone());
				}

				ctx.constrain_to_constant(zs.last().unwrap().clone(), F::zero())?;

				Ok(self.x.clone())
			},
		)
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

	fn synthesize(
		self, common: &crate::CommonConfig, config: &LookupRangeCheckChipsetConfig,
		mut layouter: impl halo2::circuit::Layouter<F>,
	) -> Result<Self::Output, halo2::plonk::Error> {
		// First, check if x is less than 256 bits
		let range_chip = LookupRangeCheckChip::<F, K, N>::new(self.x.clone());
		let x = range_chip.synthesize(
			common,
			&config.q_running_sum,
			layouter.namespace(|| "x long range check"),
		)?;

		// Rip the last word of "x" & chek if it is 4 bit
		let last_word = {
			let num_bits = K * N;
			// Take first num_bits bits of `element`.
			let bits = x
				.value()
				.map(|element| element.to_le_bits().into_iter().take(num_bits).collect::<Vec<_>>());

			let words = bits
				.map(|bits| {
					bits.chunks_exact(K)
						.map(|word| F::from(lebs2ip::<K>(&(word.try_into().unwrap()))))
						.collect::<Vec<_>>()
				})
				.transpose_vec(N);

			words[N - 1]
		};

		let last_word_cell = layouter.assign_region(
			|| "last word of x",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				ctx.assign_advice(common.advice[0], last_word)
			},
		)?;
		let short_word_chip = LookupShortWordCheckChip::<F, K, S>::new(last_word_cell);
		let _ = short_word_chip.synthesize(
			common,
			&config.q_short_word,
			layouter.namespace(|| "x last word check"),
		)?;

		Ok(x)
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

	const K: usize = 8;
	const S: usize = 3;
	const N: usize = 2;

	#[derive(Debug, Clone)]
	enum Gadget {
		ShortWordCheck,
		RangeCheck,
	}

	#[derive(Clone)]
	struct TestConfig {
		common: CommonConfig,
		q_bitshift: Selector,
		q_running_sum: Selector,
	}

	#[derive(Clone)]
	struct TestCircuit {
		x: Fr,
		gadget: Gadget,
	}

	impl TestCircuit {
		fn new(x: Fr, gadget: Gadget) -> Self {
			Self { x, gadget }
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
			let q_bitshift = LookupShortWordCheckChip::<Fr, K, S>::configure(&common, meta);
			let q_running_sum = LookupRangeCheckChip::<Fr, K, N>::configure(&common, meta);

			TestConfig { common, q_bitshift, q_running_sum }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			// Loads the values [0..2^K) into `common.table`.
			layouter.assign_table(
				|| "table_column",
				|mut table| {
					// We generate the row values lazily (we only need them during keygen).
					for index in 0..(1 << K) {
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

			match self.gadget {
				Gadget::ShortWordCheck => {
					let short_word_check_chip = LookupShortWordCheckChip::<Fr, K, S>::new(x);
					let _ = short_word_check_chip.synthesize(
						&config.common,
						&config.q_bitshift,
						layouter.namespace(|| "short word check"),
					)?;
				},
				Gadget::RangeCheck => {
					let range_check_chip = LookupRangeCheckChip::<Fr, K, N>::new(x);
					let _ = range_check_chip.synthesize(
						&config.common,
						&config.q_running_sum,
						layouter.namespace(|| "range check"),
					)?;
				},
			}

			Ok(())
		}
	}

	#[test]
	fn test_short_word_case() {
		// Testing x is 3 bits
		let x = Fr::from(0b111);

		let test_chip = TestCircuit::new(x, Gadget::ShortWordCheck);

		let k = 9;
		let pub_ins = vec![];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert!(prover.verify().is_ok());

		// Should fail since x is 4 bits
		let x = Fr::from(0b1001);

		let test_chip = TestCircuit::new(x, Gadget::ShortWordCheck);

		let k = 9;
		let pub_ins = vec![];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert!(prover.verify().is_err());
	}

	#[test]
	fn test_range_check() {
		// Testing x is 16 bits
		let x = Fr::from(0b1111111111111100);

		let test_chip = TestCircuit::new(x, Gadget::RangeCheck);

		let k = 9;
		let pub_ins = vec![];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert!(prover.verify().is_ok());

		// Should fail since x is 15 bits
		let x = Fr::from(0b11111111111111111);

		let test_chip = TestCircuit::new(x, Gadget::RangeCheck);

		let k = 9;
		let pub_ins = vec![];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert!(prover.verify().is_err());
	}
}
