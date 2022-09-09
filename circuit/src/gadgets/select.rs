use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region},
	plonk::{Advice, Column, ConstraintSystem, Error, Selector},
	poly::Rotation,
};

use super::is_boolean::IsBooleanChip;
use crate::gadgets::is_boolean::IsBooleanConfig;

#[derive(Clone, Debug)]
/// Configuration elements for the circuit defined here.
pub struct SelectConfig {
	/// Constructs is_bool circuit elements.
	is_bool: IsBooleanConfig,
	/// Configures a column for the bit.
	bit: Column<Advice>,
	/// Configures a column for the x.
	x: Column<Advice>,
	/// Configures a column for the y.
	y: Column<Advice>,
	/// Configures a fixed boolean value for each row of the circuit.
	selector: Selector,
}

/// Constructs individual cells for the configuration elements.
pub struct SelectChip<F: FieldExt> {
	/// Assigns a cell for the bits.
	bit: AssignedCell<F, F>,
	/// Assigns a cell for the x.
	x: AssignedCell<F, F>,
	/// Assigns a cell for the y.
	y: AssignedCell<F, F>,
}

impl<F: FieldExt> SelectChip<F> {
	/// Create a new chip.
	pub fn new(bit: AssignedCell<F, F>, x: AssignedCell<F, F>, y: AssignedCell<F, F>) -> Self {
		SelectChip { bit, x, y }
	}

	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> SelectConfig {
		let boolean_config = IsBooleanChip::configure(meta);
		let bit = meta.advice_column();
		let x = meta.advice_column();
		let y = meta.advice_column();
		let s = meta.selector();

		meta.enable_equality(bit);
		meta.enable_equality(x);
		meta.enable_equality(y);

		meta.create_gate("select", |v_cells| {
			let bit_exp = v_cells.query_advice(bit, Rotation::cur());
			let x_exp = v_cells.query_advice(x, Rotation::cur());
			let y_exp = v_cells.query_advice(y, Rotation::cur());

			let res_exp = v_cells.query_advice(x, Rotation::next());

			let s_exp = v_cells.query_selector(s);

			vec![
				// bit * (x - y) - (z - y)
				// Example 1:
				// bit = 1
				// Cell for z will carry the same value with x when bit == 1. (x == z)
				// x = 5
				// y = 3
				// z = 5
				// 1 * (x - y) - (z - y) = 1 * (5 - 3) - (5 - 3) = 0
				// Example 2:
				// bit = 0
				// Cell for z will carry the same value with y when bit == 0. (y == z)
				// x = 5
				// y = 3
				// z = 3
				// 0 * (x - y) - (z - y) = 0 * (5 - 3) - (3 - 3) = 0
				// When the bit is 0 and one of the variables are non-zero,
				// constraint returns a non-zero value.
				s_exp * (bit_exp.clone() * (x_exp - y_exp.clone()) - (res_exp - y_exp)),
			]
		});

		SelectConfig {
			is_bool: boolean_config,
			bit,
			x,
			y,
			selector: s,
		}
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self,
		config: SelectConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		let is_boolean_chip = IsBooleanChip::new(self.bit.clone());
		// Here we check bit is boolean or not.
		let assigned_bool = is_boolean_chip
			.synthesize(config.is_bool.clone(), layouter.namespace(|| "is_boolean"))?;

		layouter.assign_region(
			|| "select",
			|mut region: Region<'_, F>| {
				config.selector.enable(&mut region, 0)?;

				let assigned_bit =
					assigned_bool.copy_advice(|| "bit", &mut region, config.bit, 0)?;
				let assigned_x = self.x.copy_advice(|| "x", &mut region, config.x, 0)?;
				let assigned_y = self.y.copy_advice(|| "y", &mut region, config.y, 0)?;

				// Conditional control checks the bit. Is it zero or not?
				// If yes returns the y value, else x.
				let res = assigned_bit.value().and_then(|bit_f| {
					if bool::from(bit_f.is_zero()) {
						assigned_y.value().cloned()
					} else {
						assigned_x.value().cloned()
					}
				});

				let assigned_res = region.assign_advice(|| "res", config.x, 1, || res)?;

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
	struct TestConfig {
		select: SelectConfig,
		temp: Column<Advice>,
		pub_ins: Column<Instance>,
	}

	#[derive(Clone)]
	struct TestCircuit<F: FieldExt> {
		x: F,
		y: F,
		bit: F,
	}

	impl<F: FieldExt> TestCircuit<F> {
		fn new(bit: F, x: F, y: F) -> Self {
			Self { bit, x, y }
		}
	}

	impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
			let select = SelectChip::configure(meta);
			let temp = meta.advice_column();
			let pub_ins = meta.instance_column();

			meta.enable_equality(temp);
			meta.enable_equality(pub_ins);

			TestConfig {
				select,
				temp,
				pub_ins,
			}
		}

		fn synthesize(
			&self,
			config: TestConfig,
			mut layouter: impl Layouter<F>,
		) -> Result<(), Error> {
			let (assigned_bit, assigned_x, assigned_y) = layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, F>| {
					let bit = region.assign_advice(
						|| "temp_bit",
						config.temp,
						0,
						|| Value::known(self.bit),
					)?;
					let x = region.assign_advice(
						|| "temp_x",
						config.temp,
						1,
						|| Value::known(self.x),
					)?;
					let y = region.assign_advice(
						|| "temp_y",
						config.temp,
						2,
						|| Value::known(self.y),
					)?;

					Ok((bit, x, y))
				},
			)?;
			let select_chip = SelectChip::new(assigned_bit, assigned_x, assigned_y);
			let res = select_chip.synthesize(config.select, layouter.namespace(|| "select"))?;

			layouter.constrain_instance(res.cell(), config.pub_ins, 0)?;
			Ok(())
		}
	}

	#[test]
	fn test_select() {
		// Testing bit = 0.
		let test_chip = TestCircuit::new(Fr::from(0), Fr::from(2), Fr::from(3));

		let pub_ins = vec![Fr::from(3)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_select_one_as_bit() {
		// Testing bit = 1.
		let test_chip = TestCircuit::new(Fr::from(1), Fr::from(7), Fr::from(4));

		let pub_ins = vec![Fr::from(7)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_select_two_as_bit() {
		// Testing bit = 2. Constraint not satisfied error will return because bit is
		// not a boolean value.
		let test_chip = TestCircuit::new(Fr::from(2), Fr::from(3), Fr::from(6));

		let pub_ins = vec![Fr::from(3)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert!(prover.verify().is_err());
	}

	#[test]
	fn test_select_production() {
		let test_chip = TestCircuit::new(Fr::from(0), Fr::from(2), Fr::from(3));

		let k = 4;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::from(3)]], rng).unwrap();

		assert!(res);
	}
}
