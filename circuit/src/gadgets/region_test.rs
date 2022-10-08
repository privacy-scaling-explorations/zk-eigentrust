use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region},
	plonk::{Advice, Column, ConstraintSystem, Error, Selector},
	poly::Rotation,
};
use std::marker::PhantomData;

#[derive(Copy, Clone, Debug)]
/// Configuration elements for the circuit are defined here.
pub struct TestRegionConfig {
	/// Configures columns for the advice.
	advice: [Column<Advice>; 2],
	/// Configures fixed boolean values for each row of the circuit.
	selectors: [Selector; 2],
}

/// Structure for the chip.
pub struct TestRegionChip<F: FieldExt> {
	/// Constructs a phantom data for the FieldExt.
	_phantom: PhantomData<F>,
}

impl<F: FieldExt> TestRegionChip<F> {
	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> TestRegionConfig {
		let advice = [meta.advice_column(), meta.advice_column()];
		let selectors = [meta.selector(), meta.selector()];
		advice.map(|c| meta.enable_equality(c));

		meta.create_gate("sum", |v_cells| {
			let sum_exp = v_cells.query_advice(advice[0], Rotation::cur());
			let item_exp = v_cells.query_advice(advice[1], Rotation::cur());
			let sum_next = v_cells.query_advice(advice[0], Rotation::next());

			let s = v_cells.query_selector(selectors[0]);
			// (x + y) - z == 0
			// z is the next rotation cell for the x value.
			// Example:
			// let x = 2;
			// let y = 1;
			// let z = (x + y);
			// z;
			//
			// z = (2 + 1) = 3 => Checking the constraint (2 + 1) - 3 == 0
			vec![s * (sum_exp + item_exp - sum_next)]
		});

		// Gate for the mul circuit.
		meta.create_gate("mul", |v_cells| {
			let x_exp = v_cells.query_advice(advice[0], Rotation::cur());
			let y_exp = v_cells.query_advice(advice[1], Rotation::cur());
			let z_exp = v_cells.query_advice(advice[0], Rotation::next());
			let s_exp = v_cells.query_selector(selectors[1]);

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

		TestRegionConfig { advice, selectors }
	}

	/// Synthesize the sum circuit.
	pub fn sum(
		x: AssignedCell<F, F>, y: AssignedCell<F, F>, config: TestRegionConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		layouter.assign_region(
			|| "sum",
			|mut region: Region<'_, F>| {
				config.selectors[0].enable(&mut region, 0)?;
				let mut sum = y.copy_advice(|| "initial_sum", &mut region, config.advice[0], 0)?;
				let item = x.copy_advice(|| "item", &mut region, config.advice[1], 0)?;
				let val = sum.value().cloned() + item.value();
				sum = region.assign_advice(|| "sum", config.advice[0], 1, || val)?;

				Ok(sum)
			},
		)
	}

	/// Synthesize the mul circuit.
	pub fn mul(
		// Assigns a cell for the x.
		x: AssignedCell<F, F>,
		// Assigns a cell for the y.
		y: AssignedCell<F, F>,
		config: TestRegionConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		layouter.assign_region(
			|| "mul",
			|mut region: Region<'_, F>| {
				config.selectors[1].enable(&mut region, 0)?;
				let assigned_x = x.copy_advice(|| "x", &mut region, config.advice[0], 0)?;
				let assigned_y = y.copy_advice(|| "y", &mut region, config.advice[1], 0)?;

				let out = assigned_x.value().cloned() * assigned_y.value();

				let out_assigned = region.assign_advice(|| "out", config.advice[0], 1, || out)?;

				Ok(out_assigned)
			},
		)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use halo2wrong::{
		curves::bn256::Fr,
		halo2::{
			circuit::{SimpleFloorPlanner, Value},
			dev::MockProver,
			plonk::{Circuit, Instance},
		},
	};

	#[derive(Clone)]
	enum Gadgets {
		Sum,
		Mul,
	}

	#[derive(Clone)]
	struct TestConfig {
		test_region: TestRegionConfig,
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
			let test_region = TestRegionChip::configure(meta);
			println!("{:#?}", test_region);
			let temp = meta.advice_column();
			let pub_ins = meta.instance_column();
			meta.enable_equality(temp);
			meta.enable_equality(pub_ins);

			TestConfig { test_region, pub_ins, temp }
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
				Gadgets::Mul => {
					let mul = TestRegionChip::mul(
						items[0].clone(),
						items[1].clone(),
						config.test_region,
						layouter.namespace(|| "mul"),
					)?;
					layouter.constrain_instance(mul.cell(), config.pub_ins, 0)?;
				},
				Gadgets::Sum => {
					let acc = TestRegionChip::sum(
						items[0].clone(),
						items[1].clone(),
						config.test_region,
						layouter.namespace(|| "sum"),
					)?;
					layouter.constrain_instance(acc.cell(), config.pub_ins, 0)?;
				},
			}

			Ok(())
		}
	}

	#[test]
	fn test_mul_sum() {
		// Testing x = 5 and y = 2.
		let test_chip_mul = TestCircuit::new([Fr::from(5), Fr::from(2)], Gadgets::Mul);
		// Testing three 2's representation on the field as an input.
		let test_chip_sum = TestCircuit::new([Fr::from(8), Fr::from(2)], Gadgets::Sum);

		let k = 4;
		let pub_ins = vec![Fr::from(10)];
		let prover_mul = MockProver::run(k, &test_chip_mul, vec![pub_ins.clone()]).unwrap();
		let prover_sum = MockProver::run(k, &test_chip_sum, vec![pub_ins]).unwrap();
		assert_eq!(prover_mul.verify(), prover_sum.verify());
	}
}
