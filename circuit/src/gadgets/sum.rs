use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region},
	plonk::{Advice, Column, ConstraintSystem, Error, Selector},
	poly::Rotation,
};

#[derive(Clone, Debug)]
/// Configuration elements for the circuit defined here.
pub struct SumConfig {
	/// Configures a column for the sum.
	sum: Column<Advice>,
	/// Configures a column for the items.
	items: Column<Advice>,
	/// Configures a fixed boolean value for each row of the circuit.
	selector: Selector,
}
/// Constructs individual cells for the configuration elements.
pub struct SumChip<F: FieldExt, const S: usize> {
	/// Assigns a cell for the items.
	items: [AssignedCell<F, F>; S],
}

impl<F: FieldExt, const S: usize> SumChip<F, S> {
	/// Create a new chip.
	pub fn new(items: [AssignedCell<F, F>; S]) -> Self {
		SumChip { items }
	}

	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> SumConfig {
		let sum = meta.advice_column();
		let items = meta.advice_column();
		let fixed = meta.fixed_column();
		let s = meta.selector();

		meta.enable_equality(sum);
		meta.enable_equality(items);
		meta.enable_constant(fixed);

		meta.create_gate("sum", |v_cells| {
			let sum_exp = v_cells.query_advice(sum, Rotation::cur());
			let item_exp = v_cells.query_advice(items, Rotation::cur());
			let sum_next = v_cells.query_advice(sum, Rotation::next());

			let s = v_cells.query_selector(s);
			// (x + y) - z == 0
			// z is the next rotation cell for the x value.
			// Example for a sum gate:
			// let x = 2;
			// let y = 1;
			// let z = (x + y);
			// z;
			//
			// z = (2 + 1) = 3 => We check the constraint (2 + 1) - 3 == 0
			vec![s * (sum_exp + item_exp - sum_next)]
		});

		SumConfig {
			sum,
			items,
			selector: s,
		}
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self,
		config: SumConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		layouter.assign_region(
			|| "sum",
			|mut region: Region<'_, F>| {
				config.selector.enable(&mut region, 0)?;
				let mut sum = region.assign_advice_from_constant(
					|| "initial_sum",
					config.sum,
					0,
					F::zero(),
				)?;

				// This circuit can take many inputs. It will loop and accumulate all of the
				// items to the sum value.
				for i in 0..S {
					config.selector.enable(&mut region, i)?;
					let item =
						self.items[i].copy_advice(|| "item", &mut region, config.items, i)?;
					let val = sum.value().cloned() + item.value();
					sum = region.assign_advice(|| "sum", config.sum, i + 1, || val)?;
				}

				Ok(sum)
			},
		)
	}
}

#[cfg(test)]
mod test {
	use std::usize;

	use super::*;
	use crate::utils::{generate_params, prove_and_verify};
	use halo2wrong::{
		curves::bn256::{Bn256, Fr},
		halo2::{
			arithmetic::Field,
			circuit::{SimpleFloorPlanner, Value},
			dev::MockProver,
			plonk::{Circuit, Instance},
		},
	};

	#[derive(Clone)]
	struct TestConfig {
		sum: SumConfig,
		temp: Column<Advice>,
		pub_ins: Column<Instance>,
	}

	#[derive(Clone)]
	struct TestCircuit<F: FieldExt, const S: usize> {
		items: [F; S],
	}

	impl<F: FieldExt, const S: usize> TestCircuit<F, S> {
		fn new(items: [F; S]) -> Self {
			Self { items }
		}
	}

	impl<F: FieldExt, const S: usize> Circuit<F> for TestCircuit<F, S> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
			let sum = SumChip::<_, S>::configure(meta);
			let temp = meta.advice_column();
			let pub_ins = meta.instance_column();

			meta.enable_equality(temp);
			meta.enable_equality(pub_ins);

			TestConfig { sum, temp, pub_ins }
		}

		fn synthesize(
			&self,
			config: TestConfig,
			mut layouter: impl Layouter<F>,
		) -> Result<(), Error> {
			let arr = layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, F>| {
					let mut arr: [Option<AssignedCell<F, F>>; S] = [(); S].map(|_| None);
					for i in 0..S {
						arr[i] = Some(region.assign_advice(
							|| "temp",
							config.temp,
							i,
							|| Value::known(self.items[i]),
						)?);
					}
					Ok(arr.map(|a| a.unwrap()))
				},
			)?;
			let sum_chip = SumChip::new(arr);
			let acc = sum_chip.synthesize(config.sum, layouter.namespace(|| "sum"))?;

			layouter.constrain_instance(acc.cell(), config.pub_ins, 0)?;
			Ok(())
		}
	}

	#[test]
	fn test_sum() {
		// Testing three 2's representation on the field as an input.
		let test_chip = TestCircuit::new([Fr::from(2); 3]);

		let k = 4;
		let pub_ins = vec![Fr::from(6)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_sum_random_element() {
		// Testing big array with a random element from the field.
		let array = [(); 512].map(|_| <Fr as Field>::random(rand::thread_rng()));
		let test_chip = TestCircuit::new(array);
		let mut ins: Vec<Fr> = vec![Fr::from(0)];
		for i in 0..512 {
			let temp = array[i];
			ins[0] = ins[0].add(&temp);
		}
		let k = 10;
		let prover = MockProver::run(k, &test_chip, vec![ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_sum_zero_arr() {
		// Testing zero array. Returns CellNotAssigned error.
		let test_chip = TestCircuit::new([]);

		let pub_ins = vec![Fr::from(0)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert!(prover.verify().is_err());
	}

	#[test]
	fn test_sum_production() {
		let test_chip = TestCircuit::new([Fr::from(2); 3]);

		let k = 4;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		assert_eq!(
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::from(6)]], rng).unwrap(),
			true
		);
	}
}
