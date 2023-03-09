use halo2::{
	circuit::{AssignedCell, Layouter, Region, Value},
	halo2curves::FieldExt,
	plonk::{
		Advice, Column, ConstraintSystem, Constraints, Error, Fixed, Instance, Selector,
		TableColumn,
	},
	poly::Rotation,
};

use crate::{
	utils::{fe_to_le_bits, lebs2ip},
	RegionCtx,
};

/// Number of advice columns in common config
const ADVICE: usize = 3;
/// Number of fixed columns in common config
const FIXED: usize = 1;

/// Common config for the whole circuit
#[derive(Clone, Debug)]
pub struct MockCommonConfig {
	/// Advice columns
	advice: [Column<Advice>; ADVICE],
	/// Fixed columns
	fixed: [Column<Fixed>; FIXED],
	/// Instance column
	instance: Column<Instance>,
	/// Lookup table column
	table: TableColumn,
}

impl MockCommonConfig {
	/// Create a new `MockCommonConfig` columns
	pub fn new<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
		let advice = [(); ADVICE].map(|_| meta.advice_column());
		let fixed = [(); FIXED].map(|_| meta.fixed_column());
		let instance = meta.instance_column();
		let table = meta.lookup_table_column();

		advice.map(|c| meta.enable_equality(c));
		fixed.map(|c| meta.enable_constant(c));
		meta.enable_equality(instance);

		Self { advice, fixed, instance, table }
	}
}

/// Trait for an atomic chip implementation
/// Each chip uses common config columns, but has its own selector
pub trait MockChip<F: FieldExt> {
	/// Output of the synthesis
	type Output: Clone;
	/// Gate configuration, using common config columns
	fn configure(common: &MockCommonConfig, meta: &mut ConstraintSystem<F>) -> Selector;
	/// Chip synthesis. This function can return an assigned cell to be used
	/// elsewhere in the circuit
	fn synthesize(
		self, common: &MockCommonConfig, selector: &Selector, layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error>;
}

/// Chipset uses a collection of chips as primitives to build more abstract
/// circuits
pub trait MockChipset<F: FieldExt> {
	/// Config used for synthesis
	type Config: Clone;
	/// Output of the synthesis
	type Output: Clone;
	/// Chipset synthesis. This function can have multiple smaller chips
	/// synthesised inside. Also can returns an assigned cell.
	fn synthesize(
		self, common: &MockCommonConfig, config: &Self::Config, layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error>;
}

/// Short length bits check chip using lookup table.
///
/// Checks if the target value is `S` bits long.
#[derive(Debug, Clone)]
pub struct LookupShortWordCheckChip<F: FieldExt, const K: usize, const S: usize> {
	x: AssignedCell<F, F>,
}

impl<F: FieldExt, const K: usize, const S: usize> LookupShortWordCheckChip<F, K, S> {
	/// Construct new instance
	pub fn new(x: AssignedCell<F, F>) -> Self {
		Self { x }
	}
}

impl<F: FieldExt, const K: usize, const S: usize> MockChip<F>
	for LookupShortWordCheckChip<F, K, S>
{
	type Output = AssignedCell<F, F>;

	fn configure(
		common: &MockCommonConfig, meta: &mut halo2::plonk::ConstraintSystem<F>,
	) -> Selector {
		assert!(0 < S && S < K, "Word bits should be less than target bits.");

		let bitshift_selector = meta.complex_selector();

		let word_column = common.advice[0];

		meta.lookup("Check K bits limit", |meta| {
			let bitshift_selector = meta.query_selector(bitshift_selector);
			let shifted_word = meta.query_advice(word_column, Rotation::cur());

			vec![(bitshift_selector * shifted_word, common.table)]
		});

		// For short lookups, check that the word has been shifted by the correct number
		// of bits. https://p.z.cash/halo2-0.1:decompose-short-lookup
		meta.create_gate("Short word S bits limit", |meta| {
			let bitshift_selector = meta.query_selector(bitshift_selector);
			let word = meta.query_advice(word_column, Rotation::prev());
			let shifted_word = meta.query_advice(word_column, Rotation::cur());
			let inv_two_pow_s = meta.query_advice(word_column, Rotation::next());

			let two_pow_k = F::from(1 << K);

			// shifted_word = word * 2^{K-s}
			//              = word * 2^K * inv_two_pow_s
			Constraints::with_selector(
				bitshift_selector,
				Some(word * two_pow_k * inv_two_pow_s - shifted_word),
			)
		});

		bitshift_selector
	}

	fn synthesize(
		self, common: &MockCommonConfig, selector: &Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, halo2::plonk::Error> {
		layouter.assign_region(
			|| "short word check chip",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);

				// Assign original value
				let assigned_x = ctx.copy_assign(common.advice[0], self.x.clone())?;

				ctx.next();

				// Assign shifted value
				let shifted_word = self.x.value().cloned() * Value::known(F::from(1 << (K - S)));
				ctx.assign_advice(common.advice[0], shifted_word)?;
				ctx.enable(selector.clone())?;

				ctx.next();

				// Assign 2^{-S} from a fixed column.
				let inv_two_pow_s = F::from(1 << S).invert().unwrap();
				ctx.assign_from_constant(common.advice[0], inv_two_pow_s)?;

				Ok(assigned_x)
			},
		)
	}
}

/// Range check chip using lookup table.
///
/// Check if the target value is `K * N` bits long.
#[derive(Debug, Clone)]
pub struct LookupRangeCheckChip<F: FieldExt, const K: usize, const N: usize> {
	x: AssignedCell<F, F>,
}

impl<F: FieldExt, const K: usize, const N: usize> LookupRangeCheckChip<F, K, N> {
	/// Construct a new instance
	pub fn new(x: AssignedCell<F, F>) -> Self {
		Self { x }
	}
}

impl<F: FieldExt, const K: usize, const N: usize> MockChip<F> for LookupRangeCheckChip<F, K, N> {
	type Output = AssignedCell<F, F>;

	fn configure(
		common: &MockCommonConfig, meta: &mut halo2::plonk::ConstraintSystem<F>,
	) -> Selector {
		let running_sum_selector = meta.complex_selector();

		let running_sum = common.advice[0];

		meta.lookup("running_sum check", |meta| {
			let running_sum_selector = meta.query_selector(running_sum_selector);
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

				running_sum_selector.clone() * running_sum_word
			};

			// Combine the running sum and short lookups:
			vec![(running_sum_lookup, common.table)]
		});

		running_sum_selector
	}

	fn synthesize(
		self, common: &MockCommonConfig, selector: &Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, halo2::plonk::Error> {
		layouter.assign_region(
			|| "range check chip",
			|region: Region<'_, F>| {
				let mut ctx = RegionCtx::new(region, 0);
				let x = ctx.copy_assign(common.advice[0], self.x.clone())?;

				let num_bits = K * N;

				// Chunk the first num_bits bits into K-bit words.
				let words = {
					// Take first num_bits bits of `element`.
					let bits = x.value().map(|element| {
						fe_to_le_bits(element.clone())
							.into_iter()
							.take(num_bits)
							.collect::<Vec<_>>()
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

/// RangeChipsetConfig
#[derive(Debug, Clone)]
pub struct RangeChipsetConfig {
	running_sum_selector: Selector,
	short_word_selecor: Selector,
}

impl RangeChipsetConfig {
	/// Construct a new instance
	pub fn new(running_sum_selector: Selector, short_word_selecor: Selector) -> Self {
		Self { running_sum_selector, short_word_selecor }
	}
}

/// RangeChipset
#[derive(Debug, Clone)]
pub struct RangeChipset<F: FieldExt, const K: usize, const N: usize, const S: usize> {
	x: AssignedCell<F, F>,
}

impl<F: FieldExt, const K: usize, const N: usize, const S: usize> RangeChipset<F, K, N, S> {
	/// Constructs new chipset
	pub fn new(x: AssignedCell<F, F>) -> Self {
		Self { x }
	}
}

impl<F: FieldExt, const K: usize, const N: usize, const S: usize> MockChipset<F>
	for RangeChipset<F, K, N, S>
{
	type Config = RangeChipsetConfig;
	type Output = AssignedCell<F, F>;

	fn synthesize(
		self, common: &MockCommonConfig, config: &RangeChipsetConfig,
		mut layouter: impl halo2::circuit::Layouter<F>,
	) -> Result<Self::Output, halo2::plonk::Error> {
		// First, check if x is less than 256 bits
		let range_chip = LookupRangeCheckChip::<F, K, N>::new(self.x.clone());
		let x = range_chip.synthesize(
			common,
			&config.running_sum_selector,
			layouter.namespace(|| "range check"),
		)?;

		// Rip the last word of "x" & chek if it is 4 bit
		let last_word = {
			let num_bits = K * N;
			// Take first num_bits bits of `element`.
			let bits = x.value().map(|element| {
				fe_to_le_bits(element.clone()).into_iter().take(num_bits).collect::<Vec<_>>()
			});

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
			&config.short_word_selecor,
			layouter.namespace(|| "last word check"),
		)?;

		Ok(x)
	}
}

#[cfg(test)]
mod tests {
	use MockCommonConfig;

	use super::*;

	use halo2::{
		circuit::{Region, SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::pasta::Fp as Fr,
		plonk::{Circuit, ConstraintSystem, Error},
	};

	const K: usize = 8;
	const N: usize = 2;
	const S: usize = 3;

	#[derive(Debug, Clone)]
	enum Gadget {
		ShortWordCheck,
		RangeCheck,
		RangeChipset,
	}

	#[derive(Clone)]
	struct TestConfig {
		common: MockCommonConfig,
		short_word_selector: Selector,
		running_sum_selector: Selector,
		lookup_range_check: RangeChipsetConfig,
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
			let common = MockCommonConfig::new(meta);
			let short_word_selector =
				LookupShortWordCheckChip::<Fr, K, S>::configure(&common, meta);
			let running_sum_selector = LookupRangeCheckChip::<Fr, K, N>::configure(&common, meta);
			let lookup_range_check =
				RangeChipsetConfig::new(running_sum_selector, short_word_selector);

			TestConfig { common, short_word_selector, running_sum_selector, lookup_range_check }
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
						&config.short_word_selector,
						layouter.namespace(|| "short word check"),
					)?;
				},
				Gadget::RangeCheck => {
					let range_check_chip = LookupRangeCheckChip::<Fr, K, N>::new(x);
					let _ = range_check_chip.synthesize(
						&config.common,
						&config.running_sum_selector,
						layouter.namespace(|| "range check"),
					)?;
				},
				Gadget::RangeChipset => {
					let lookup_range_check_chipset = RangeChipset::<Fr, K, N, S>::new(x);
					let _ = lookup_range_check_chipset.synthesize(
						&config.common,
						&config.lookup_range_check,
						layouter.namespace(|| "lookup range check chipset"),
					)?;
				},
			}

			Ok(())
		}
	}

	#[test]
	fn test_short_word_case() {
		let k = 9;
		let pub_ins = vec![];

		// Testing x is 3 bits
		let x = Fr::from(0x07); // 0b111

		let test_chip = TestCircuit::new(x, Gadget::ShortWordCheck);
		let prover = MockProver::run(k, &test_chip, vec![pub_ins.clone()]).unwrap();
		assert!(prover.verify().is_ok());

		// Should fail since x is 4 bits
		let x = Fr::from(0x09); // 0b1001

		let test_chip = TestCircuit::new(x, Gadget::ShortWordCheck);
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert!(prover.verify().is_err());
	}

	#[test]
	fn test_range_check() {
		let k = 9;
		let pub_ins = vec![];

		// Testing x is 16 bits
		let x = Fr::from(0xffff); // 0b1111111111111111

		let test_chip = TestCircuit::new(x, Gadget::RangeCheck);
		let prover = MockProver::run(k, &test_chip, vec![pub_ins.clone()]).unwrap();
		assert!(prover.verify().is_ok());

		// Should fail since x is 17 bits
		let x = Fr::from(0x10000); // 0b10000000000000000

		let test_chip = TestCircuit::new(x, Gadget::RangeCheck);
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert!(prover.verify().is_err());
	}

	#[test]
	fn test_lookup_range_check_chipset() {
		let k = 9;
		let pub_ins = vec![];

		// Testing x is 11 bits
		let x = Fr::from(0x7ff); // 0b11111111111

		let test_chip = TestCircuit::new(x, Gadget::RangeChipset);
		let prover = MockProver::run(k, &test_chip, vec![pub_ins.clone()]).unwrap();
		assert!(prover.verify().is_ok());

		// Should fail since x is 12 bits
		let x = Fr::from(0xfff); // 0b111111111111

		let test_chip = TestCircuit::new(x, Gadget::RangeChipset);
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert!(prover.verify().is_err());
	}
}
