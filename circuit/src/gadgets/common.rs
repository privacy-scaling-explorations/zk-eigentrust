use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};
use std::marker::PhantomData;

#[derive(Copy, Clone, Debug)]
/// Configuration elements for the circuit are defined here.
pub struct CommonConfig {
	/// Configures columns for the advice.
	advice: [Column<Advice>; 3],
	/// Configures fixed boolean values for each row of the circuit.
	selectors: [Selector; 6],
}

/// Structure for the chip.
pub struct CommonChip<F: FieldExt> {
	/// Constructs a phantom data for the FieldExt.
	_phantom: PhantomData<F>,
}

impl<F: FieldExt> CommonChip<F> {
	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> CommonConfig {
		let advice = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
		let selectors = [
			meta.selector(),
			meta.selector(),
			meta.selector(),
			meta.selector(),
			meta.selector(),
			meta.selector(),
		];

		advice.map(|c| meta.enable_equality(c));

		// Gate for the and circuit.
		meta.create_gate("and", |v_cells| {
			let x_exp = v_cells.query_advice(advice[0], Rotation::cur());
			let y_exp = v_cells.query_advice(advice[1], Rotation::cur());
			let res_exp = v_cells.query_advice(advice[2], Rotation::cur());
			let s_exp = v_cells.query_selector(selectors[0]);

			vec![
				// (x * y) - z == 0
				// Example:
				// let x = 1;
				// let y = 0;
				// let z = (x * y);
				// z;
				//
				// z = (1 * 0) = 0 => Checking the constraint (1 * 0) - 0 == 0
				s_exp * ((x_exp * y_exp) - res_exp),
			]
		});

		// Gate for the is_bool circuit.
		meta.create_gate("is_bool", |v_cells| {
			let one = Expression::Constant(F::one());
			let x_exp = v_cells.query_advice(advice[0], Rotation::cur());
			let s_exp = v_cells.query_selector(selectors[1]);

			vec![
				// (1 - x) * x == 0
				// Only two valid examples exist for a boolean gate.
				// Circuit working only on current rotation cells.
				// First example:
				// If x = 1,
				// (1 - 1) * 1 == 0 => Checking the constraint 0 * 1 == 0
				// Second example:
				// If x = 0,
				// (1 - 0) * 0 == 0 => Checking the constraint 1 * 0 == 0
				s_exp * ((one - x_exp.clone()) * x_exp),
			]
		});

		// Gate for the is_equal circuit.
		meta.create_gate("is_equal", |v_cells| {
			let lhs_exp = v_cells.query_advice(advice[0], Rotation::cur());
			let rhs_exp = v_cells.query_advice(advice[1], Rotation::cur());
			let out_exp = v_cells.query_advice(advice[2], Rotation::cur());
			let s_exp = v_cells.query_selector(selectors[2]);

			vec![
				// (x + y) - z == 0
				// Example:
				// let y = 123;
				// let z = 123;
				// let x = (y - z);
				// x;
				//
				// x = (123 - 123) = 0 => Checking the constraint (0 + 123) - 123 == 0
				s_exp * ((out_exp + rhs_exp) - lhs_exp),
			]
		});

		// Gate for the is_zero circuit.
		meta.create_gate("is_zero", |v_cells| {
			let one = Expression::Constant(F::one());
			let x_exp = v_cells.query_advice(advice[0], Rotation::cur());
			let x_inv_exp = v_cells.query_advice(advice[1], Rotation::cur());
			let b_exp = v_cells.query_advice(advice[2], Rotation::cur());
			let sel_exp = v_cells.query_selector(selectors[3]);

			vec![
				// x * b == 0
				// Checking this constraint to be sure
				// that one of the variable is equal to 0.
				// b is the boolean and desired output is (x == 0)
				sel_exp.clone() * (x_exp.clone() * b_exp.clone()),
				// x * x_inv + b - 1 == 0
				// Example 1:
				// If x = 1 => x_inv = 1,
				// (1 * 1 + b - 1) == 0
				// In this case, b must be equal to 0.
				// Example 2:
				// If b = 1,
				// (x * x_inv + 1 - 1) == 0 => (x * x_inv) must be equal to 0.
				// Which is only can be obtainable by x = 0.
				sel_exp * (x_exp * x_inv_exp + b_exp - one),
			]
		});

		// Gate for the mul circuit.
		meta.create_gate("mul", |v_cells| {
			let x_exp = v_cells.query_advice(advice[0], Rotation::cur());
			let y_exp = v_cells.query_advice(advice[1], Rotation::cur());
			let z_exp = v_cells.query_advice(advice[2], Rotation::cur());
			let s_exp = v_cells.query_selector(selectors[4]);

			vec![
				// (x * y) - z == 0
				// Example:
				// let x = 3;
				// let y = 2;
				// let z = (x * y);
				// z;
				//
				// z = (3 * 2) = 6 => Checking the constraint (3 * 2) - 6 == 0
				s_exp * ((x_exp * y_exp) - z_exp),
			]
		});

		// Gate for the select circuit.
		meta.create_gate("select", |v_cells| {
			let bit_exp = v_cells.query_advice(advice[0], Rotation::cur());
			let x_exp = v_cells.query_advice(advice[1], Rotation::cur());
			let y_exp = v_cells.query_advice(advice[2], Rotation::cur());
			let res_exp = v_cells.query_advice(advice[1], Rotation::next());
			let s_exp = v_cells.query_selector(selectors[5]);

			vec![
				// bit * (x - y) - (z - y)
				// Example 1:
				// bit = 1
				// z will carry the same value with x when bit == 1. (x == z)
				// x = 5
				// y = 3
				// z = 5
				// 1 * (x - y) - (z - y) = 1 * (5 - 3) - (5 - 3) = 0
				// Example 2:
				// bit = 0
				// z will carry the same value with y when bit == 0. (y == z)
				// x = 5
				// y = 3
				// z = 3
				// 0 * (x - y) - (z - y) = 0 * (5 - 3) - (3 - 3) = 0
				s_exp * (bit_exp.clone() * (x_exp - y_exp.clone()) - (res_exp - y_exp)),
			]
		});

		CommonConfig { advice, selectors }
	}

	/// Synthesize the and circuit.
	pub fn and(
		// Assigns a cell for the x.
		x: AssignedCell<F, F>,
		// Assigns a cell for the y.
		y: AssignedCell<F, F>,
		config: CommonConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		// Here we check our values x and y.
		// Both of the values have to be boolean.
		let x_checked = Self::is_bool(x, config.clone(), layouter.namespace(|| "is_bool_x"))?;
		let y_checked = Self::is_bool(y, config, layouter.namespace(|| "is_bool_y"))?;

		layouter.assign_region(
			|| "and",
			|mut region: Region<'_, F>| {
				config.selectors[0].enable(&mut region, 0)?;

				let assigned_x = x_checked.copy_advice(|| "x", &mut region, config.advice[0], 0)?;
				let assigned_y = y_checked.copy_advice(|| "y", &mut region, config.advice[1], 0)?;

				let res = assigned_x.value().cloned() * assigned_y.value();

				let res_assigned = region.assign_advice(|| "res", config.advice[2], 0, || res)?;

				Ok(res_assigned)
			},
		)
	}

	/// Synthesize the is_bool circuit.
	pub fn is_bool(
		// Assigns a cell for the x.
		x: AssignedCell<F, F>,
		config: CommonConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		layouter.assign_region(
			|| "is_boolean",
			|mut region: Region<'_, F>| {
				config.selectors[1].enable(&mut region, 0)?;
				let assigned_x = x.copy_advice(|| "x", &mut region, config.advice[0], 0)?;

				Ok(assigned_x)
			},
		)
	}

	/// Synthesize the is_equal circuit.
	pub fn is_equal(
		// Assigns a cell for the lhs.
		lhs: AssignedCell<F, F>,
		// Assigns a cell for the rhs.
		rhs: AssignedCell<F, F>,
		config: CommonConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		let out = layouter.assign_region(
			|| "temp",
			|mut region: Region<'_, F>| {
				config.selectors[2].enable(&mut region, 0)?;
				let assigned_lhs = lhs.copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
				let assigned_rhs = rhs.copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;

				let out = assigned_lhs.value().cloned() - assigned_rhs.value();

				let assigned_out = region.assign_advice(|| "lhs", config.advice[2], 0, || out)?;
				Ok(assigned_out)
			},
		)?;

		// If variable out holds 0 as value, that means is_zero circuit will return 1.
		let is_zero = Self::is_zero(out, config, layouter.namespace(|| "is_zero"))?;
		Ok(is_zero)
	}

	/// Synthesize the is_zero circuit.
	pub fn is_zero(
		// Assigns a cell for the x.
		x: AssignedCell<F, F>,
		config: CommonConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		let is_zero = layouter.assign_region(
			|| "is_zero",
			|mut region: Region<'_, F>| {
				config.selectors[3].enable(&mut region, 0)?;

				let one = Value::known(F::one());
				let x_inv = x.value().and_then(|val| {
					let val_opt: Option<F> = val.invert().into();
					Value::known(val_opt.unwrap_or(F::one()))
				});
				// In the circuit here, if x = 0, b will be assigned to the value 1.
				// If x = 1, means x_inv = 1 as well, b will be assigned to the value 0.
				let b = one - x.value().cloned() * x_inv;

				x.copy_advice(|| "x", &mut region, config.advice[0], 0)?;
				region.assign_advice(|| "x_inv", config.advice[1], 0, || x_inv)?;
				let assigned_b = region.assign_advice(|| "b", config.advice[2], 0, || b)?;

				Ok(assigned_b)
			},
		)?;

		Ok(is_zero)
	}

	/// Synthesize the mul circuit.
	pub fn mul(
		// Assigns a cell for the x.
		x: AssignedCell<F, F>,
		// Assigns a cell for the y.
		y: AssignedCell<F, F>,
		config: CommonConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		layouter.assign_region(
			|| "mul",
			|mut region: Region<'_, F>| {
				config.selectors[4].enable(&mut region, 0)?;
				let assigned_x = x.copy_advice(|| "x", &mut region, config.advice[0], 0)?;
				let assigned_y = y.copy_advice(|| "y", &mut region, config.advice[1], 0)?;

				let out = assigned_x.value().cloned() * assigned_y.value();

				let out_assigned = region.assign_advice(|| "out", config.advice[2], 0, || out)?;

				Ok(out_assigned)
			},
		)
	}

	/// Synthesize the select circuit.
	pub fn select(
		// Assigns a cell for the bit.
		bit: AssignedCell<F, F>,
		// Assigns a cell for the x.
		x: AssignedCell<F, F>,
		// Assigns a cell for the y.
		y: AssignedCell<F, F>,
		config: CommonConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		// Checking bit is boolean or not.
		let assigned_bool = Self::is_bool(bit, config, layouter.namespace(|| "is_boolean"))?;

		layouter.assign_region(
			|| "select",
			|mut region: Region<'_, F>| {
				config.selectors[5].enable(&mut region, 0)?;

				let assigned_bit =
					assigned_bool.copy_advice(|| "bit", &mut region, config.advice[0], 0)?;
				let assigned_x = x.copy_advice(|| "x", &mut region, config.advice[1], 0)?;
				let assigned_y = y.copy_advice(|| "y", &mut region, config.advice[2], 0)?;

				// Conditional control checks the bit. Is it zero or not?
				// If yes returns the y value, else x.
				let res = assigned_bit.value().and_then(|bit_f| {
					if bool::from(bit_f.is_zero()) {
						assigned_y.value().cloned()
					} else {
						assigned_x.value().cloned()
					}
				});

				let assigned_res = region.assign_advice(|| "res", config.advice[1], 1, || res)?;

				Ok(assigned_res)
			},
		)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::utils::{generate_params, prove_and_verify};
	use halo2wrong::{
		curves::bn256::{Bn256, Fr},
		halo2::{
			circuit::{SimpleFloorPlanner, Value},
			dev::MockProver,
			plonk::{Circuit, Instance},
		},
	};

	#[derive(Clone)]
	enum Gadgets {
		And,
		IsBool,
		IsEqual,
		IsZero,
		Mul,
		Select,
	}

	#[derive(Clone)]
	struct TestConfig {
		common: CommonConfig,
		temp: Column<Advice>,
		pub_ins: Column<Instance>,
	}

	#[derive(Clone)]
	struct TestCircuit<F: FieldExt, const N: usize> {
		inputs: [F; N],
		gadget: Gadgets,
	}

	impl<F: FieldExt, const N: usize> TestCircuit<F, N> {
		fn new(inputs: [F; N], gadget: Gadgets) -> Self {
			Self { inputs, gadget }
		}
	}

	impl<F: FieldExt, const N: usize> Circuit<F> for TestCircuit<F, N> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
			let common = CommonChip::configure(meta);
			let temp = meta.advice_column();
			let pub_ins = meta.instance_column();
			meta.enable_equality(temp);
			meta.enable_equality(pub_ins);

			TestConfig { common, pub_ins, temp }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<F>,
		) -> Result<(), Error> {
			let mut items = Vec::new();
			for i in 0..N {
				items.push(layouter.assign_region(
					|| "temp",
					|mut region: Region<'_, F>| {
						let x = region.assign_advice(
							|| "temp_inputs",
							config.temp,
							i,
							|| Value::known(self.inputs[i]),
						)?;
						Ok(x)
					},
				)?);
			}

			match self.gadget {
				Gadgets::And => {
					let and = CommonChip::and(
						items[0].clone(),
						items[1].clone(),
						config.common,
						layouter.namespace(|| "and"),
					)?;
					layouter.constrain_instance(and.cell(), config.pub_ins, 0)?;
				},
				Gadgets::IsBool => {
					CommonChip::is_bool(
						items[0].clone(),
						config.common,
						layouter.namespace(|| "is_bool"),
					)?;
				},
				Gadgets::IsEqual => {
					let is_equal = CommonChip::is_equal(
						items[0].clone(),
						items[1].clone(),
						config.common,
						layouter.namespace(|| "is_zero"),
					)?;
					layouter.constrain_instance(is_equal.cell(), config.pub_ins, 0)?;
				},
				Gadgets::IsZero => {
					let is_zero = CommonChip::is_zero(
						items[0].clone(),
						config.common,
						layouter.namespace(|| "is_zero"),
					)?;
					layouter.constrain_instance(is_zero.cell(), config.pub_ins, 0)?;
				},
				Gadgets::Mul => {
					let mul = CommonChip::mul(
						items[0].clone(),
						items[1].clone(),
						config.common,
						layouter.namespace(|| "mul"),
					)?;
					layouter.constrain_instance(mul.cell(), config.pub_ins, 0)?;
				},
				Gadgets::Select => {
					let select = CommonChip::select(
						items[0].clone(),
						items[1].clone(),
						items[2].clone(),
						config.common,
						layouter.namespace(|| "select"),
					)?;
					layouter.constrain_instance(select.cell(), config.pub_ins, 0)?;
				},
			}

			Ok(())
		}
	}

	// AND CIRCUIT TESTS
	#[test]
	fn test_and_x1_y1() {
		// Testing x = 1 and y = 1.
		let test_chip = TestCircuit::new([Fr::from(1), Fr::from(1)], Gadgets::And);

		let pub_ins = vec![Fr::from(1)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_and_x1_y0() {
		// Testing x = 1 and y = 0.
		let test_chip = TestCircuit::new([Fr::from(1), Fr::from(0)], Gadgets::And);

		let pub_ins = vec![Fr::from(0)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_and_x0_y0() {
		// Testing x = 0 and y = 0.
		let test_chip = TestCircuit::new([Fr::from(0), Fr::from(0)], Gadgets::And);

		let pub_ins = vec![Fr::from(0)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_and_x0_y1() {
		// Testing x = 0 and y = 1.
		let test_chip = TestCircuit::new([Fr::from(0), Fr::from(1)], Gadgets::And);

		let pub_ins = vec![Fr::from(0)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_and_production() {
		let test_chip = TestCircuit::new([Fr::from(1), Fr::from(1)], Gadgets::And);

		let k = 4;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::from(1)]], rng).unwrap();

		assert!(res);
	}

	// IS_BOOL CIRCUIT TESTS
	#[test]
	fn test_is_bool_value_zero() {
		// Testing input zero as value.
		let test_chip = TestCircuit::new([Fr::from(0)], Gadgets::IsBool);

		let k = 4;
		let dummy_instance = vec![Fr::zero()];
		let prover = MockProver::run(k, &test_chip, vec![dummy_instance]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_bool_value_one() {
		// Testing input one as value.
		let test_chip = TestCircuit::new([Fr::from(1)], Gadgets::IsBool);

		let k = 4;
		let dummy_instance = vec![Fr::zero()];
		let prover = MockProver::run(k, &test_chip, vec![dummy_instance]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_bool_invalid_value() {
		// Testing input two as value, which is invalid for the boolean circuit.
		let test_chip = TestCircuit::new([Fr::from(2)], Gadgets::IsBool);

		let k = 4;
		let dummy_instance = vec![Fr::zero()];
		let prover = MockProver::run(k, &test_chip, vec![dummy_instance]).unwrap();
		assert!(prover.verify().is_err());
	}

	#[test]
	fn test_is_bool_production() {
		let test_chip = TestCircuit::new([Fr::from(0)], Gadgets::IsBool);

		let k = 4;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let dummy_instance = vec![Fr::zero()];
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&dummy_instance], rng).unwrap();

		assert!(res);
	}

	// IS_EQUAL CIRCUIT TESTS
	#[test]
	fn test_is_equal() {
		// Testing equal values.
		let test_chip = TestCircuit::new([Fr::from(123), Fr::from(123)], Gadgets::IsEqual);

		let pub_ins = vec![Fr::one()];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_not_equal() {
		// Testing not equal values.
		let test_chip = TestCircuit::new([Fr::from(123), Fr::from(124)], Gadgets::IsEqual);

		let pub_ins = vec![Fr::zero()];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_equal_production() {
		let test_chip = TestCircuit::new([Fr::from(123), Fr::from(123)], Gadgets::IsEqual);

		let k = 4;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::one()]], rng).unwrap();

		assert!(res);
	}

	// IS_ZERO CIRCUIT TESTS
	#[test]
	fn test_is_zero() {
		// Testing zero as value.
		let test_chip = TestCircuit::new([Fr::from(0)], Gadgets::IsZero);

		let pub_ins = vec![Fr::one()];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_zero_not() {
		// Testing a non-zero value.
		let test_chip = TestCircuit::new([Fr::from(1)], Gadgets::IsZero);

		let pub_ins = vec![Fr::zero()];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_zero_production() {
		let test_chip = TestCircuit::new([Fr::from(0)], Gadgets::IsZero);

		let k = 4;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::one()]], rng).unwrap();

		assert!(res);
	}

	// MUL CIRCUIT TESTS
	#[test]
	fn test_mul() {
		// Testing x = 5 and y = 2.
		let test_chip = TestCircuit::new([Fr::from(5), Fr::from(2)], Gadgets::Mul);

		let k = 4;
		let pub_ins = vec![Fr::from(10)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_mul_y1() {
		// Testing x = 3 and y = 1.
		let test_chip = TestCircuit::new([Fr::from(3), Fr::from(1)], Gadgets::Mul);

		let k = 4;
		let pub_ins = vec![Fr::from(3)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_mul_y0() {
		// Testing x = 4 and y = 0.
		let test_chip = TestCircuit::new([Fr::from(4), Fr::from(0)], Gadgets::Mul);

		let k = 4;
		let pub_ins = vec![Fr::from(0)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_mul_production() {
		let test_chip = TestCircuit::new([Fr::from(5), Fr::from(2)], Gadgets::Mul);

		let k = 4;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::from(10)]], rng).unwrap();

		assert!(res);
	}

	// SELECT CIRCUIT TESTS
	#[test]
	fn test_select() {
		// Testing bit = 0.
		let test_chip = TestCircuit::new([Fr::from(0), Fr::from(2), Fr::from(3)], Gadgets::Select);

		let pub_ins = vec![Fr::from(3)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_select_one_as_bit() {
		// Testing bit = 1.
		let test_chip = TestCircuit::new([Fr::from(1), Fr::from(7), Fr::from(4)], Gadgets::Select);

		let pub_ins = vec![Fr::from(7)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_select_two_as_bit() {
		// Testing bit = 2. Constraint not satisfied error will return
		// because the bit is not a boolean value.
		let test_chip = TestCircuit::new([Fr::from(2), Fr::from(3), Fr::from(6)], Gadgets::Select);

		let pub_ins = vec![Fr::from(3)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert!(prover.verify().is_err());
	}

	#[test]
	fn test_select_production() {
		let test_chip = TestCircuit::new([Fr::from(0), Fr::from(2), Fr::from(3)], Gadgets::Select);

		let k = 4;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::from(3)]], rng).unwrap();

		assert!(res);
	}
}
