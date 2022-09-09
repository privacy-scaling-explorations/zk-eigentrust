use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region},
	plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};

/// Configuration elements for the circuit defined here.
#[derive(Clone, Debug)]
pub struct IsBooleanConfig {
	/// Configures a column for the x.
	x: Column<Advice>,
	/// Configures a fixed boolean value for each row of the circuit.
	selector: Selector,
}

/// Constructs individual cell for the configuration element.
pub struct IsBooleanChip<F: FieldExt> {
	/// Assigns a cell for the x.
	x: AssignedCell<F, F>,
}

impl<F: FieldExt> IsBooleanChip<F> {
	/// Create a new chip.
	pub fn new(x: AssignedCell<F, F>) -> Self {
		IsBooleanChip { x }
	}

	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> IsBooleanConfig {
		let x = meta.advice_column();
		let s = meta.selector();

		meta.enable_equality(x);

		meta.create_gate("is_bool", |v_cells| {
			let one = Expression::Constant(F::one());
			let x_exp = v_cells.query_advice(x, Rotation::cur());
			let s_exp = v_cells.query_selector(s);

			vec![
				// (1 - x) * x == 0
				// Only two valid example exist for a boolean gate
				// We only work on current rotation cells
				// First example:
				// let x = 1;
				// (1 - 1) * 1 == 0 => We check the constraint 0 * 1 == 0
				// Second example:
				// let x = 0;
				// (1 - 0) * 0 == 0 => We check the constraint 1 * 0 == 0
				s_exp * ((one - x_exp.clone()) * x_exp),
			]
		});

		IsBooleanConfig { x, selector: s }
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self, config: IsBooleanConfig, mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		layouter.assign_region(
			|| "is_boolean",
			|mut region: Region<'_, F>| {
				config.selector.enable(&mut region, 0)?;
				let assigned_x = self.x.copy_advice(|| "x", &mut region, config.x, 0)?;

				Ok(assigned_x)
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
			plonk::Circuit,
		},
	};

	#[derive(Clone)]
	struct TestConfig {
		is_bool: IsBooleanConfig,
		temp: Column<Advice>,
	}

	#[derive(Clone)]
	struct TestCircuit<F: FieldExt> {
		numba: F,
	}

	impl<F: FieldExt> TestCircuit<F> {
		fn new(x: F) -> Self {
			Self { numba: x }
		}
	}

	impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
			let is_bool = IsBooleanChip::configure(meta);
			let temp = meta.advice_column();

			meta.enable_equality(temp);

			TestConfig { is_bool, temp }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<F>,
		) -> Result<(), Error> {
			let numba = layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, F>| {
					region.assign_advice(|| "temp_x", config.temp, 0, || Value::known(self.numba))
				},
			)?;
			let is_bool_chip = IsBooleanChip::new(numba);
			is_bool_chip.synthesize(config.is_bool, layouter.namespace(|| "is_bool"))?;
			Ok(())
		}
	}

	#[test]
	fn test_is_bool_value_zero() {
		// Testing input zero as value.
		let test_chip = TestCircuit::new(Fr::from(0));

		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_bool_value_one() {
		// Testing input one as value.
		let test_chip = TestCircuit::new(Fr::from(1));

		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_bool_invalid_value() {
		// Testing input two as value, which is invalid for the boolean circuit.
		let test_chip = TestCircuit::new(Fr::from(2));

		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![]).unwrap();
		assert!(prover.verify().is_err());
	}

	#[test]
	fn test_is_bool_production() {
		let test_chip = TestCircuit::new(Fr::from(0));

		let k = 4;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, test_chip, &[], rng).unwrap();

		assert!(res);
	}
}
