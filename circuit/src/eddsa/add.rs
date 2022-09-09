use super::native::ops::{add_exp, add_value};
use halo2wrong::{
	curves::bn256::Fr,
	halo2::{
		circuit::{AssignedCell, Layouter, Region},
		plonk::{Advice, Column, ConstraintSystem, Error, Selector},
		poly::Rotation,
	},
};

#[derive(Clone)]
pub struct PointAddConfig {
	r_x: Column<Advice>,
	r_y: Column<Advice>,
	r_z: Column<Advice>,
	e_x: Column<Advice>,
	e_y: Column<Advice>,
	e_z: Column<Advice>,
	selector: Selector,
}

#[derive(Clone)]
pub struct PointAddChip {
	r_x: AssignedCell<Fr, Fr>,
	r_y: AssignedCell<Fr, Fr>,
	r_z: AssignedCell<Fr, Fr>,
	e_x: AssignedCell<Fr, Fr>,
	e_y: AssignedCell<Fr, Fr>,
	e_z: AssignedCell<Fr, Fr>,
}

impl PointAddChip {
	pub fn new(
		r_x: AssignedCell<Fr, Fr>, r_y: AssignedCell<Fr, Fr>, r_z: AssignedCell<Fr, Fr>,
		e_x: AssignedCell<Fr, Fr>, e_y: AssignedCell<Fr, Fr>, e_z: AssignedCell<Fr, Fr>,
	) -> Self {
		Self { r_x, r_y, r_z, e_x, e_y, e_z }
	}
}

impl PointAddChip {
	pub fn configure(meta: &mut ConstraintSystem<Fr>) -> PointAddConfig {
		let r_x = meta.advice_column();
		let r_y = meta.advice_column();
		let r_z = meta.advice_column();
		let e_x = meta.advice_column();
		let e_y = meta.advice_column();
		let e_z = meta.advice_column();
		let s = meta.selector();

		meta.enable_equality(r_x);
		meta.enable_equality(r_y);
		meta.enable_equality(r_z);
		meta.enable_equality(e_x);
		meta.enable_equality(e_y);
		meta.enable_equality(e_z);

		meta.create_gate("point_add", |v_cells| {
			let s_exp = v_cells.query_selector(s);

			let r_x_exp = v_cells.query_advice(r_x, Rotation::cur());
			let r_y_exp = v_cells.query_advice(r_y, Rotation::cur());
			let r_z_exp = v_cells.query_advice(r_z, Rotation::cur());

			let e_x_exp = v_cells.query_advice(e_x, Rotation::cur());
			let e_y_exp = v_cells.query_advice(e_y, Rotation::cur());
			let e_z_exp = v_cells.query_advice(e_z, Rotation::cur());

			let r_x_next_exp = v_cells.query_advice(r_x, Rotation::next());
			let r_y_next_exp = v_cells.query_advice(r_y, Rotation::next());
			let r_z_next_exp = v_cells.query_advice(r_z, Rotation::next());

			let (r_x3, r_y3, r_z3) = add_exp(
				r_x_exp.clone(),
				r_y_exp.clone(),
				r_z_exp.clone(),
				e_x_exp.clone(),
				e_y_exp.clone(),
				e_z_exp.clone(),
			);

			vec![
				// Ensure the point addition of `r` and `e` is properly calculated
				s_exp.clone() * (r_x_next_exp - r_x3),
				s_exp.clone() * (r_y_next_exp - r_y3),
				s_exp.clone() * (r_z_next_exp - r_z3),
			]
		});

		PointAddConfig { r_x, r_y, r_z, e_x, e_y, e_z, selector: s }
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self, config: PointAddConfig, mut layouter: impl Layouter<Fr>,
	) -> Result<
		(
			AssignedCell<Fr, Fr>,
			AssignedCell<Fr, Fr>,
			AssignedCell<Fr, Fr>,
		),
		Error,
	> {
		layouter.assign_region(
			|| "add",
			|mut region: Region<'_, Fr>| {
				config.selector.enable(&mut region, 0)?;

				let r_x = self.r_x.copy_advice(|| "r_x", &mut region, config.r_x, 0)?;
				let r_y = self.r_y.copy_advice(|| "r_y", &mut region, config.r_y, 0)?;
				let r_z = self.r_z.copy_advice(|| "r_z", &mut region, config.r_z, 0)?;
				let e_x = self.e_x.copy_advice(|| "e_x", &mut region, config.e_x, 0)?;
				let e_y = self.e_y.copy_advice(|| "e_y", &mut region, config.e_y, 0)?;
				let e_z = self.e_z.copy_advice(|| "e_z", &mut region, config.e_z, 0)?;

				// Add `r` and `e`
				let (r_x3, r_y3, r_z3) = add_value(
					r_x.value_field(),
					r_y.value_field(),
					r_z.value_field(),
					e_x.value_field(),
					e_y.value_field(),
					e_z.value_field(),
				);

				let r_x_res = region.assign_advice(|| "r_x", config.r_x, 1, || r_x3.evaluate())?;
				let r_y_res = region.assign_advice(|| "r_y", config.r_y, 1, || r_y3.evaluate())?;
				let r_z_res = region.assign_advice(|| "r_z", config.r_z, 1, || r_z3.evaluate())?;

				Ok((r_x_res, r_y_res, r_z_res))
			},
		)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		eddsa::native::{
			ed_on_bn254::{B8, G},
			ops::add,
		},
		utils::{generate_params, prove_and_verify},
	};
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
		add: PointAddConfig,
		pub_ins: Column<Instance>,
		temp: Column<Advice>,
	}

	#[derive(Clone)]
	struct TestCircuit {
		r_x: Value<Fr>,
		r_y: Value<Fr>,
		r_z: Value<Fr>,
		e_x: Value<Fr>,
		e_y: Value<Fr>,
		e_z: Value<Fr>,
	}

	impl TestCircuit {
		fn new(r_x: Fr, r_y: Fr, r_z: Fr, e_x: Fr, e_y: Fr, e_z: Fr) -> Self {
			Self {
				r_x: Value::known(r_x),
				r_y: Value::known(r_y),
				r_z: Value::known(r_z),
				e_x: Value::known(e_x),
				e_y: Value::known(e_y),
				e_z: Value::known(e_z),
			}
		}
	}

	impl Circuit<Fr> for TestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			let add = PointAddChip::configure(meta);
			let temp = meta.advice_column();
			let instance = meta.instance_column();

			meta.enable_equality(instance);
			meta.enable_equality(temp);

			TestConfig { add, pub_ins: instance, temp }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let (r_x, r_y, r_z, e_x, e_y, e_z) = layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, Fr>| {
					let r_x_assigned =
						region.assign_advice(|| "temp_x", config.temp, 0, || self.r_x)?;
					let r_y_assigned =
						region.assign_advice(|| "temp_y", config.temp, 1, || self.r_y)?;
					let r_z_assigned =
						region.assign_advice(|| "temp_z", config.temp, 2, || self.r_z)?;

					let e_x_assigned =
						region.assign_advice(|| "temp_x", config.temp, 3, || self.e_x)?;
					let e_y_assigned =
						region.assign_advice(|| "temp_y", config.temp, 4, || self.e_y)?;
					let e_z_assigned =
						region.assign_advice(|| "temp_z", config.temp, 5, || self.e_z)?;

					Ok((
						r_x_assigned, r_y_assigned, r_z_assigned, e_x_assigned, e_y_assigned,
						e_z_assigned,
					))
				},
			)?;
			let add_chip = PointAddChip::new(r_x, r_y, r_z, e_x, e_y, e_z);
			let (x, y, z) = add_chip.synthesize(config.add, layouter.namespace(|| "add"))?;
			layouter.constrain_instance(x.cell(), config.pub_ins, 0)?;
			layouter.constrain_instance(y.cell(), config.pub_ins, 1)?;
			layouter.constrain_instance(z.cell(), config.pub_ins, 2)?;
			Ok(())
		}
	}

	#[test]
	fn should_add_point() {
		let r = B8.projective();
		let e = G.projective();
		let (x_res, y_res, z_res) = add(r.x, r.y, r.z, e.x, e.y, e.z);
		let circuit = TestCircuit::new(r.x, r.y, r.z, e.x, e.y, e.z);

		let k = 7;
		let pub_ins = vec![x_res, y_res, z_res];
		let prover = MockProver::run(k, &circuit, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_add_point_production() {
		let r = B8.projective();
		let e = G.projective();
		let (x_res, y_res, z_res) = add(r.x, r.y, r.z, e.x, e.y, e.z);
		let circuit = TestCircuit::new(r.x, r.y, r.z, e.x, e.y, e.z);

		let k = 9;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let pub_ins = [x_res, y_res, z_res];
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[&pub_ins], rng).unwrap();

		assert!(res);
	}
}
