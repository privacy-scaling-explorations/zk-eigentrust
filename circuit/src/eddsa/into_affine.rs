use halo2wrong::{
	curves::bn256::Fr,
	halo2::{
		circuit::{AssignedCell, Layouter, Region},
		plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
		poly::Rotation,
	},
};

#[derive(Clone)]
pub struct IntoAffineConfig {
	advice: [Column<Advice>; 3],
	selector: Selector,
}

#[derive(Clone)]
pub struct IntoAffineChip {
	r_x: AssignedCell<Fr, Fr>,
	r_y: AssignedCell<Fr, Fr>,
	r_z: AssignedCell<Fr, Fr>,
}

impl IntoAffineChip {
	pub fn new(
		r_x: AssignedCell<Fr, Fr>, r_y: AssignedCell<Fr, Fr>, r_z: AssignedCell<Fr, Fr>,
	) -> Self {
		Self { r_x, r_y, r_z }
	}
}

impl IntoAffineChip {
	pub fn configure(meta: &mut ConstraintSystem<Fr>) -> IntoAffineConfig {
		let advice = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
		let s = meta.selector();

		advice.map(|c| meta.enable_equality(c));

		meta.create_gate("into_affine", |v_cells| {
			let s_exp = v_cells.query_selector(s);

			let one = Expression::Constant(Fr::one());
			let r_x_exp = v_cells.query_advice(advice[0], Rotation::cur());
			let r_y_exp = v_cells.query_advice(advice[1], Rotation::cur());
			let r_z_exp = v_cells.query_advice(advice[2], Rotation::cur());

			let r_x_affine_exp = v_cells.query_advice(advice[0], Rotation::next());
			let r_y_affine_exp = v_cells.query_advice(advice[1], Rotation::next());
			let r_z_invert_exp = v_cells.query_advice(advice[2], Rotation::next());

			let affine_x = r_x_exp * r_z_invert_exp.clone();
			let affine_y = r_y_exp * r_z_invert_exp.clone();

			vec![
				s_exp.clone() * (r_x_affine_exp - affine_x),
				s_exp.clone() * (r_y_affine_exp - affine_y),
				s_exp * (r_z_exp * r_z_invert_exp - one),
			]
		});

		IntoAffineConfig { advice, selector: s }
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self, config: IntoAffineConfig, mut layouter: impl Layouter<Fr>,
	) -> Result<(AssignedCell<Fr, Fr>, AssignedCell<Fr, Fr>), Error> {
		layouter.assign_region(
			|| "into_affine",
			|mut region: Region<'_, Fr>| {
				config.selector.enable(&mut region, 0)?;

				self.r_x.copy_advice(|| "r_x", &mut region, config.advice[0], 0)?;
				self.r_y.copy_advice(|| "r_y", &mut region, config.advice[1], 0)?;
				self.r_z.copy_advice(|| "r_z", &mut region, config.advice[2], 0)?;

				let z_invert = self.r_z.value_field().invert();
				let r_x_affine = self.r_x.value_field() * z_invert;
				let r_y_affine = self.r_y.value_field() * z_invert;

				let x = region.assign_advice(
					|| "r_x_affine",
					config.advice[0],
					1,
					|| r_x_affine.evaluate(),
				)?;
				let y = region.assign_advice(
					|| "r_y_affine",
					config.advice[1],
					1,
					|| r_y_affine.evaluate(),
				)?;
				region.assign_advice(
					|| "r_z_invert",
					config.advice[2],
					1,
					|| z_invert.evaluate(),
				)?;

				Ok((x, y))
			},
		)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		eddsa::native::ed_on_bn254::B8,
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
		into_affine: IntoAffineConfig,
		pub_ins: Column<Instance>,
		temp: Column<Advice>,
	}

	#[derive(Clone)]
	struct TestCircuit {
		r_x: Value<Fr>,
		r_y: Value<Fr>,
		r_z: Value<Fr>,
	}

	impl TestCircuit {
		fn new(r_x: Fr, r_y: Fr, r_z: Fr) -> Self {
			Self { r_x: Value::known(r_x), r_y: Value::known(r_y), r_z: Value::known(r_z) }
		}
	}

	impl Circuit<Fr> for TestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			let into_affine = IntoAffineChip::configure(meta);
			let temp = meta.advice_column();
			let instance = meta.instance_column();

			meta.enable_equality(instance);
			meta.enable_equality(temp);

			TestConfig { into_affine, pub_ins: instance, temp }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let (r_x, r_y, r_z) = layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, Fr>| {
					let r_x_assigned =
						region.assign_advice(|| "temp_x", config.temp, 0, || self.r_x)?;
					let r_y_assigned =
						region.assign_advice(|| "temp_y", config.temp, 1, || self.r_y)?;
					let r_z_assigned =
						region.assign_advice(|| "temp_z", config.temp, 2, || self.r_z)?;

					Ok((r_x_assigned, r_y_assigned, r_z_assigned))
				},
			)?;
			let into_affine_chip = IntoAffineChip::new(r_x, r_y, r_z);
			let (x, y) = into_affine_chip
				.synthesize(config.into_affine, layouter.namespace(|| "into_affine"))?;
			layouter.constrain_instance(x.cell(), config.pub_ins, 0)?;
			layouter.constrain_instance(y.cell(), config.pub_ins, 1)?;
			Ok(())
		}
	}

	#[test]
	fn should_into_affine_point() {
		let r = B8.projective();
		let r_affine = r.affine();
		let circuit = TestCircuit::new(r.x, r.y, r.z);

		let k = 7;
		let pub_ins = vec![r_affine.x, r_affine.y];
		let prover = MockProver::run(k, &circuit, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_into_affine_point_production() {
		let r = B8.projective();
		let r_affine = r.affine();
		let circuit = TestCircuit::new(r.x, r.y, r.z);

		let k = 9;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let pub_ins = vec![r_affine.x, r_affine.y];
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[&pub_ins], rng).unwrap();

		assert!(res);
	}
}
