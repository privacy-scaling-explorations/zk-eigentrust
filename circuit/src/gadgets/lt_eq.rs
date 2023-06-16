use super::{bits2num::Bits2NumChip, main::MainConfig};
use crate::{
	gadgets::main::IsZeroChipset, utils::to_wide, Chip, Chipset, CommonConfig, FieldExt, RegionCtx,
};
use halo2::{
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};
use std::vec;

/// 1 << 252
pub const N_SHIFTED: [u8; 32] = [
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
];
/// Numbers are limited to 252 to avoid overflow
pub const NUM_BITS: usize = 252;
/// Same number of bits as N_SHIFTED, since NUM + N_SHIFTED is the operation.
pub const DIFF_BITS: usize = 253;

/// Chip for finding the difference between 2 numbers with size of 252 bits
pub struct NShiftedChip<F: FieldExt> {
	x: AssignedCell<F, F>,
	y: AssignedCell<F, F>,
}

impl<F: FieldExt> NShiftedChip<F> {
	/// Constructs a new chip
	pub fn new(x: AssignedCell<F, F>, y: AssignedCell<F, F>) -> Self {
		Self { x, y }
	}
}

impl<F: FieldExt> Chip<F> for NShiftedChip<F> {
	type Output = AssignedCell<F, F>;

	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector {
		let selector = meta.selector();
		let n_shifted = F::from_uniform_bytes(&to_wide(&N_SHIFTED));

		meta.create_gate("x + n_shifted - y", |v_cells| {
			let n_shifted_exp = Expression::Constant(n_shifted);

			let s_exp = v_cells.query_selector(selector);
			let x_exp = v_cells.query_advice(common.advice[0], Rotation::cur());
			let y_exp = v_cells.query_advice(common.advice[1], Rotation::cur());
			let res_exp = v_cells.query_advice(common.advice[2], Rotation::cur());

			vec![
				// (x + n_shifted - y) - z == 0
				// n_shifted value is equal to smallest 253 bit number.
				// Because of that calculations will be done in between the 252 to 254-bit range.
				// That range can hold 252-bit number calculations without overflowing.
				// Example:
				// x = 5;
				// y = 3;
				// z = (x + n_shifted - y);
				// z = (5 - 3) + n_shifted = 2 + n_shifted =>
				// diff_bits holds (x + n_shifted - y) as bits.
				// After that, checking the constraint diff_bits - z = 0.
				s_exp * ((x_exp + n_shifted_exp - y_exp) - res_exp),
			]
		});

		selector
	}

	fn synthesize(
		self, common: &CommonConfig, selector: &Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		layouter.assign_region(
			|| "less_than_equal",
			|region: Region<'_, F>| {
				let mut ctx = RegionCtx::new(region, 0);
				ctx.enable(*selector)?;

				let assigned_x = ctx.copy_assign(common.advice[0], self.x.clone())?;
				let assigned_y = ctx.copy_assign(common.advice[1], self.y.clone())?;

				let n_shifted = Value::known(F::from_uniform_bytes(&to_wide(&N_SHIFTED)));
				let res = assigned_x.value().cloned() + n_shifted - assigned_y.value();

				let assigned_res = ctx.assign_advice(common.advice[2], res)?;

				Ok(assigned_res)
			},
		)
	}
}

#[derive(Clone, Debug)]
/// Selectors for LessEqualChipset
pub struct LessEqualConfig {
	main: MainConfig,
	bits_2_num_selector: Selector,
	n_shifted_selector: Selector,
}

impl LessEqualConfig {
	/// Constructs new config
	pub fn new(
		main: MainConfig, bits_2_num_selector: Selector, n_shifted_selector: Selector,
	) -> Self {
		Self { main, bits_2_num_selector, n_shifted_selector }
	}
}

/// A chip for checking if number is in range
pub struct LessEqualChipset<F: FieldExt> {
	x: AssignedCell<F, F>,
	y: AssignedCell<F, F>,
}

impl<F: FieldExt> LessEqualChipset<F> {
	/// Constructs a new chipset
	pub fn new(x: AssignedCell<F, F>, y: AssignedCell<F, F>) -> Self {
		Self { x, y }
	}
}

impl<F: FieldExt> Chipset<F> for LessEqualChipset<F> {
	type Config = LessEqualConfig;
	type Output = AssignedCell<F, F>;

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		let x_b2n = Bits2NumChip::new_exact::<NUM_BITS>(self.x.clone());
		let _ = x_b2n.synthesize(
			common,
			&config.bits_2_num_selector,
			layouter.namespace(|| "x_b2n"),
		)?;

		let y_b2n = Bits2NumChip::new_exact::<NUM_BITS>(self.y.clone());
		let _ = y_b2n.synthesize(
			common,
			&config.bits_2_num_selector,
			layouter.namespace(|| "y_b2n"),
		)?;

		let n_shifted_chip = NShiftedChip::new(self.x, self.y);
		let inp = n_shifted_chip.synthesize(
			common,
			&config.n_shifted_selector,
			layouter.namespace(|| "n_shifted_diff"),
		)?;

		let diff_b2n = Bits2NumChip::new_exact::<DIFF_BITS>(inp);
		let bits = diff_b2n.synthesize(
			common,
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
		let res =
			is_zero_chip.synthesize(common, &config.main, layouter.namespace(|| "is_zero"))?;
		Ok(res)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		gadgets::main::MainChip,
		utils::{generate_params, prove_and_verify},
	};
	use halo2::{
		circuit::{SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::{
			bn256::{Bn256, Fr},
			ff::FromUniformBytes,
		},
		plonk::Circuit,
	};

	#[derive(Clone)]
	struct TestConfig {
		common: CommonConfig,
		lt_eq: LessEqualConfig,
	}

	#[derive(Clone)]
	struct TestCircuit {
		x: Value<Fr>,
		y: Value<Fr>,
	}

	impl TestCircuit {
		fn new(x: Fr, y: Fr) -> Self {
			Self { x: Value::known(x), y: Value::known(y) }
		}
	}

	impl Circuit<Fr> for TestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { x: Value::unknown(), y: Value::unknown() }
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			let common = CommonConfig::new(meta);
			let main = MainConfig::new(MainChip::configure(&common, meta));

			let b2n_selector = Bits2NumChip::configure(&common, meta);
			let ns_selector = NShiftedChip::configure(&common, meta);
			let lt_eq = LessEqualConfig::new(main, b2n_selector, ns_selector);

			TestConfig { common, lt_eq }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let (x, y) = layouter.assign_region(
				|| "temp",
				|region: Region<'_, Fr>| {
					let mut ctx = RegionCtx::new(region, 0);
					let x = ctx.assign_advice(config.common.advice[0], self.x)?;
					let y = ctx.assign_advice(config.common.advice[1], self.y)?;
					Ok((x, y))
				},
			)?;
			let lt_eq_chip = LessEqualChipset::<Fr>::new(x, y);
			let res = lt_eq_chip.synthesize(
				&config.common,
				&config.lt_eq,
				layouter.namespace(|| "less_eq"),
			)?;

			layouter.constrain_instance(res.cell(), config.common.instance, 0)?;
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
