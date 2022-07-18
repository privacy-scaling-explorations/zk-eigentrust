use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region},
	plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};

#[derive(Clone)]
pub struct SelectConfig {
	bit: Column<Advice>,
	x: Column<Advice>,
	y: Column<Advice>,
	selector: Selector,
}

pub struct SelectChip<F: FieldExt> {
	bit: AssignedCell<F, F>,
	x: AssignedCell<F, F>,
	y: AssignedCell<F, F>,
}

impl<F: FieldExt> SelectChip<F> {
	pub fn new(bit: AssignedCell<F, F>, x: AssignedCell<F, F>, y: AssignedCell<F, F>) -> Self {
		SelectChip { bit, x, y }
	}

	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> SelectConfig {
		let bit = meta.advice_column();
		let x = meta.advice_column();
		let y = meta.advice_column();
		let s = meta.selector();

		meta.enable_equality(bit);
		meta.enable_equality(x);
		meta.enable_equality(y);

		meta.create_gate("select", |v_cells| {
			let one = Expression::Constant(F::one());

			let bit_exp = v_cells.query_advice(bit, Rotation::cur());
			let x_exp = v_cells.query_advice(x, Rotation::cur());
			let y_exp = v_cells.query_advice(y, Rotation::cur());

			let res_exp = v_cells.query_advice(x, Rotation::next());

			let s_exp = v_cells.query_selector(s);

			vec![
				// (1 - bit) * bit == 0
				s_exp.clone() * ((one - bit_exp.clone()) * bit_exp.clone()),
				// bit * (a - b) - (r - b)
				s_exp * (bit_exp.clone() * (x_exp - y_exp.clone()) - (res_exp - y_exp)),
			]
		});

		SelectConfig {
			x,
			y,
			bit,
			selector: s,
		}
	}

	/// Synthesize the circuit.
	pub fn select(
		&self,
		config: SelectConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		layouter.assign_region(
			|| "select",
			|mut region: Region<'_, F>| {
				config.selector.enable(&mut region, 0)?;

				let assigned_bit = self.bit.copy_advice(|| "bit", &mut region, config.bit, 0)?;
				let assigned_x = self.x.copy_advice(|| "x", &mut region, config.x, 0)?;
				let assigned_y = self.y.copy_advice(|| "y", &mut region, config.y, 0)?;

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
	use halo2wrong::{
		curves::bn256::Fr,
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
			let (assigned_x, assigned_y, assigned_bit) = layouter.assign_region(
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

					Ok((x, y, bit))
				},
			)?;
			let select_chip = SelectChip::new(assigned_bit, assigned_x, assigned_y);
			let res = select_chip.select(config.select, layouter.namespace(|| "select"))?;

			layouter.constrain_instance(res.cell(), config.pub_ins, 0)?;
			Ok(())
		}
	}

	#[test]
	fn test_select() {
		let test_chip = TestCircuit::new(Fr::from(1), Fr::from(2), Fr::from(3));

		let pub_ins = vec![Fr::from(2)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}
}
