use super::{
	bits2num::Bits2NumChip,
	lt_eq::NShiftedChip,
	main::MainConfig,
	range::{RangeChipset, RangeChipsetConfig},
};
use crate::FieldExt;
use crate::{gadgets::main::IsZeroChipset, Chip, Chipset, CommonConfig};
use halo2::{
	circuit::{AssignedCell, Layouter},
	plonk::{ConstraintSystem, Error, Selector, TableColumn},
};

/// Common config for the whole circuit
#[derive(Clone, Debug)]
pub struct MockCommonConfig {
	/// Common config
	pub common: CommonConfig,
	/// Table column
	pub table: TableColumn,
}

impl MockCommonConfig {
	/// Create a new `MockCommonConfig` columns
	pub fn new<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
		let common = CommonConfig::new(meta);
		let table = meta.lookup_table_column();

		Self { common, table }
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

/// Same number of bits as N_SHIFTED, since NUM + N_SHIFTED is the operation.
const DIFF_BITS: usize = 253;

/// Numbers range check uses 8-bit limb for lookup
const K: usize = 8;
/// Numbers range check uses 32(256 / 8) limbs for lookup
const N: usize = 32;
/// Numbers range check uses 4 bits, since it checks 252(256 - 4) bits long
const S: usize = 4;

#[derive(Clone, Debug)]
/// Selectors for LessEqualChipset
struct LessEqualConfig {
	main: MainConfig,
	lookup_range_check: RangeChipsetConfig,
	bits_2_num_selector: Selector,
	n_shifted_selector: Selector,
}

impl LessEqualConfig {
	/// Constructs new config
	fn new(
		main: MainConfig, lookup_range_check: RangeChipsetConfig, bits_2_num_selector: Selector,
		n_shifted_selector: Selector,
	) -> Self {
		Self { main, lookup_range_check, bits_2_num_selector, n_shifted_selector }
	}
}

/// A chip for checking if number is in range
struct LessEqualChipset<F: FieldExt> {
	x: AssignedCell<F, F>,
	y: AssignedCell<F, F>,
}

impl<F: FieldExt> LessEqualChipset<F> {
	/// Constructs a new chipset
	fn new(x: AssignedCell<F, F>, y: AssignedCell<F, F>) -> Self {
		Self { x, y }
	}
}

impl<F: FieldExt> MockChipset<F> for LessEqualChipset<F> {
	type Config = LessEqualConfig;
	type Output = AssignedCell<F, F>;

	/// Synthesize the circuit.
	fn synthesize(
		self, mock_common: &MockCommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		let lookup_range_check_chipset = RangeChipset::<F, K, N, S>::new(self.x.clone());
		let x = lookup_range_check_chipset.synthesize(
			mock_common,
			&config.lookup_range_check,
			layouter.namespace(|| "x range check"),
		)?;

		let lookup_range_check_chipset = RangeChipset::<F, K, N, S>::new(self.y.clone());
		let y = lookup_range_check_chipset.synthesize(
			mock_common,
			&config.lookup_range_check,
			layouter.namespace(|| "y range check"),
		)?;

		let n_shifted_chip = NShiftedChip::new(x, y);
		let inp = n_shifted_chip.synthesize(
			&mock_common.common,
			&config.n_shifted_selector,
			layouter.namespace(|| "n_shifted_diff"),
		)?;

		let diff_b2n = Bits2NumChip::new_exact::<DIFF_BITS>(inp);
		let bits = diff_b2n.synthesize(
			&mock_common.common,
			&config.bits_2_num_selector,
			layouter.namespace(|| "bits2num"),
		)?;

		// Check the last bit.
		// If it is 1, that means the result is bigger than 253 bits.
		// This means x is bigger than y and is_zero will return 0.
		// If it is 0, that means the result is smaller than 253 bits.
		// This means y is bigger than x and is_zero will return 1.
		// If both are equal last bit still will be 1 and the number will be exactly 253
		// bits. In that case, is_zero will return 0 as well.
		let is_zero_chip = IsZeroChipset::new(bits[DIFF_BITS - 1].clone());
		let res = is_zero_chip.synthesize(
			&mock_common.common,
			&config.main,
			layouter.namespace(|| "is_zero"),
		)?;
		Ok(res)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		gadgets::{
			lt_eq::N_SHIFTED,
			main::MainChip,
			range::{LookupRangeCheckChip, LookupShortWordCheckChip},
		},
		utils::{generate_params, prove_and_verify, to_wide},
		RegionCtx,
	};
	use halo2::{
		circuit::{Region, SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::{
			bn256::{Bn256, Fr},
			ff::FromUniformBytes,
		},
		plonk::Circuit,
	};

	#[derive(Clone)]
	struct TestConfig {
		mock_common: MockCommonConfig,
		lt_eq: LessEqualConfig,
	}

	#[derive(Clone)]
	struct TestCircuit {
		x: Fr,
		y: Fr,
	}

	impl TestCircuit {
		fn new(x: Fr, y: Fr) -> Self {
			Self { x, y }
		}
	}

	impl Circuit<Fr> for TestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			let mock_common = MockCommonConfig::new(meta);
			let main = MainConfig::new(MainChip::configure(&mock_common.common, meta));

			let range_check_selector =
				LookupRangeCheckChip::<Fr, K, N>::configure(&mock_common, meta);
			let short_word_check_selector =
				LookupShortWordCheckChip::<Fr, K, S>::configure(&mock_common, meta);
			let lookup_range_check =
				RangeChipsetConfig::new(range_check_selector, short_word_check_selector);

			let b2n_selector = Bits2NumChip::configure(&mock_common.common, meta);
			let ns_selector = NShiftedChip::configure(&mock_common.common, meta);

			let lt_eq = LessEqualConfig::new(main, lookup_range_check, b2n_selector, ns_selector);

			TestConfig { mock_common, lt_eq }
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
							config.mock_common.table,
							index,
							|| Value::known(Fr::from(index as u64)),
						)?;
					}
					Ok(())
				},
			)?;

			let (x, y) = layouter.assign_region(
				|| "temp",
				|region: Region<'_, Fr>| {
					let mut ctx = RegionCtx::new(region, 0);
					let x_val = Value::known(self.x);
					let y_val = Value::known(self.y);
					let x = ctx.assign_advice(config.mock_common.common.advice[0], x_val)?;
					let y = ctx.assign_advice(config.mock_common.common.advice[1], y_val)?;
					Ok((x, y))
				},
			)?;
			let lt_eq_chip = LessEqualChipset::<Fr>::new(x, y);
			let res = lt_eq_chip.synthesize(
				&config.mock_common,
				&config.lt_eq,
				layouter.namespace(|| "less_eq"),
			)?;

			layouter.constrain_instance(res.cell(), config.mock_common.common.instance, 0)?;
			Ok(())
		}
	}

	#[test]
	fn test_less_than_y_x() {
		// Testing x > y.
		let x = Fr::from(8);
		let y = Fr::from(4);

		let test_chip = TestCircuit::new(x, y);

		let k = 11;
		let pub_ins = vec![Fr::from(0)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_less_than_x_y() {
		// Testing x < y.
		let x = Fr::from(3);
		let y = Fr::from(9);

		let test_chip = TestCircuit::new(x, y);

		let k = 11;
		let pub_ins = vec![Fr::from(1)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_less_than_x_y_equal() {
		// Testing x = y.
		let x = Fr::from(4);
		let y = Fr::from(4);

		let test_chip = TestCircuit::new(x, y);

		let k = 11;
		let pub_ins = vec![Fr::from(0)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_less_than_x252_y() {
		// Testing x = biggest 252 bit number.
		let bit252 = Fr::from_uniform_bytes(&to_wide(&N_SHIFTED));
		let x = bit252.sub(&Fr::one());
		let y = Fr::from(9);

		let test_chip = TestCircuit::new(x, y);

		let k = 11;
		let pub_ins = vec![Fr::from(0)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_less_than_x_y252() {
		// Testing y = biggest 252 bit number.
		let bit252 = Fr::from_uniform_bytes(&to_wide(&N_SHIFTED));
		let x = Fr::from(2);
		let y = bit252.sub(&Fr::from(1));

		let test_chip = TestCircuit::new(x, y);

		let k = 11;
		let pub_ins = vec![Fr::from(1)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_less_than_x252_y252() {
		// Testing x = y = biggest 252 bit number.
		let bit252 = Fr::from_uniform_bytes(&to_wide(&N_SHIFTED));
		let x = bit252.sub(&Fr::from(1));
		let y = bit252.sub(&Fr::from(1));

		let test_chip = TestCircuit::new(x, y);

		let k = 11;
		let pub_ins = vec![Fr::from(0)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_less_than_production() {
		let x = Fr::from(8);
		let y = Fr::from(4);
		let test_chip = TestCircuit::new(x, y);

		let k = 11;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let pub_ins = [Fr::from(0)];
		let res = prove_and_verify::<Bn256, _, _>(params, test_chip, &[&pub_ins], rng).unwrap();

		assert!(res);
	}
}
