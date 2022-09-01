use super::native::ops::{add_exp, add_value, double_exp, double_value};
use crate::gadgets::bits2num::{Bits2NumChip, Bits2NumConfig};
use halo2wrong::{
	curves::bn256::Fr,
	halo2::{
		circuit::{AssignedCell, Layouter, Region},
		plonk::{Advice, Column, ConstraintSystem, Error, Selector},
		poly::Rotation,
	},
};

#[derive(Clone)]
pub struct ScalarMulConfig {
	bits2num: Bits2NumConfig,
	bits: Column<Advice>,
	r_x: Column<Advice>,
	r_y: Column<Advice>,
	r_z: Column<Advice>,
	e_x: Column<Advice>,
	e_y: Column<Advice>,
	e_z: Column<Advice>,
	selector: Selector,
}

#[derive(Clone)]
pub struct ScalarMulChip<const B: usize> {
	e_x: AssignedCell<Fr, Fr>,
	e_y: AssignedCell<Fr, Fr>,
	e_z: AssignedCell<Fr, Fr>,
	value: AssignedCell<Fr, Fr>,
	value_bits: [Fr; B],
}

impl<const B: usize> ScalarMulChip<B> {
	pub fn new(
		e_x: AssignedCell<Fr, Fr>, e_y: AssignedCell<Fr, Fr>, e_z: AssignedCell<Fr, Fr>,
		value: AssignedCell<Fr, Fr>, value_bits: [Fr; B],
	) -> Self {
		Self { e_x, e_y, e_z, value, value_bits }
	}
}

impl<const B: usize> ScalarMulChip<B> {
	pub fn configure(meta: &mut ConstraintSystem<Fr>) -> ScalarMulConfig {
		let bits2num = Bits2NumChip::<_, B>::configure(meta);
		let bits = meta.advice_column();
		let r_x = meta.advice_column();
		let r_y = meta.advice_column();
		let r_z = meta.advice_column();
		let e_x = meta.advice_column();
		let e_y = meta.advice_column();
		let e_z = meta.advice_column();
		let s = meta.selector();

		meta.enable_equality(bits);
		meta.enable_equality(r_x);
		meta.enable_equality(r_y);
		meta.enable_equality(r_z);
		meta.enable_equality(e_x);
		meta.enable_equality(e_y);
		meta.enable_equality(e_z);

		meta.create_gate("scalar_mul", |v_cells| {
			let s_exp = v_cells.query_selector(s);
			let bit_exp = v_cells.query_advice(bits, Rotation::cur());

			let r_x_exp = v_cells.query_advice(r_x, Rotation::cur());
			let r_y_exp = v_cells.query_advice(r_y, Rotation::cur());
			let r_z_exp = v_cells.query_advice(r_z, Rotation::cur());

			let e_x_exp = v_cells.query_advice(e_x, Rotation::cur());
			let e_y_exp = v_cells.query_advice(e_y, Rotation::cur());
			let e_z_exp = v_cells.query_advice(e_z, Rotation::cur());

			let r_x_next_exp = v_cells.query_advice(r_x, Rotation::next());
			let r_y_next_exp = v_cells.query_advice(r_y, Rotation::next());
			let r_z_next_exp = v_cells.query_advice(r_z, Rotation::next());

			let e_x_next_exp = v_cells.query_advice(e_x, Rotation::next());
			let e_y_next_exp = v_cells.query_advice(e_y, Rotation::next());
			let e_z_next_exp = v_cells.query_advice(e_z, Rotation::next());

			let (r_x3, r_y3, r_z3) = add_exp(
				r_x_exp.clone(),
				r_y_exp.clone(),
				r_z_exp.clone(),
				e_x_exp.clone(),
				e_y_exp.clone(),
				e_z_exp.clone(),
			);

			let (e_x3, e_y3, e_z3) = double_exp(e_x_exp, e_y_exp, e_z_exp);

			// Select the next value based on a `bit` -- see `select` gadget.
			let selected_r_x =
				bit_exp.clone() * (r_x3 - r_x_exp.clone()) - (r_x_next_exp - r_x_exp);
			let selected_r_y =
				bit_exp.clone() * (r_y3 - r_y_exp.clone()) - (r_y_next_exp - r_y_exp);
			let selected_r_z =
				bit_exp.clone() * (r_z3 - r_z_exp.clone()) - (r_z_next_exp - r_z_exp);

			vec![
				// Ensure the point addition of `r` and `e` is properly calculated
				s_exp.clone() * selected_r_x,
				s_exp.clone() * selected_r_y,
				s_exp.clone() * selected_r_z,
				// Ensure the `e` doubling is properly calculated
				s_exp.clone() * (e_x_next_exp - e_x3),
				s_exp.clone() * (e_y_next_exp - e_y3),
				s_exp * (e_z_next_exp - e_z3),
			]
		});

		ScalarMulConfig { bits2num, bits, r_x, r_y, r_z, e_x, e_y, e_z, selector: s }
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self, config: ScalarMulConfig, mut layouter: impl Layouter<Fr>,
	) -> Result<
		(
			AssignedCell<Fr, Fr>,
			AssignedCell<Fr, Fr>,
			AssignedCell<Fr, Fr>,
		),
		Error,
	> {
		let bits2num = Bits2NumChip::new(self.value.clone(), self.value_bits);
		let bits = bits2num.synthesize(config.bits2num, layouter.namespace(|| "bits2num"))?;

		layouter.assign_region(
			|| "scalar_mul",
			|mut region: Region<'_, Fr>| {
				for i in 0..bits.len() {
					bits[i].copy_advice(|| "bit", &mut region, config.bits, i)?;
				}

				let mut r_x =
					region.assign_advice_from_constant(|| "r_x_0", config.r_x, 0, Fr::zero())?;
				let mut r_y =
					region.assign_advice_from_constant(|| "r_y_0", config.r_y, 0, Fr::one())?;
				let mut r_z =
					region.assign_advice_from_constant(|| "r_z_0", config.r_z, 0, Fr::one())?;

				let mut e_x = self.e_x.copy_advice(|| "e_x", &mut region, config.e_x, 0)?;
				let mut e_y = self.e_y.copy_advice(|| "e_y", &mut region, config.e_y, 0)?;
				let mut e_z = self.e_z.copy_advice(|| "e_z", &mut region, config.e_z, 0)?;

				for i in 0..self.value_bits.len() {
					config.selector.enable(&mut region, i)?;

					// Add `r` and `e`
					let (r_x3, r_y3, r_z3) = add_value(
						r_x.value_field(),
						r_y.value_field(),
						r_z.value_field(),
						e_x.value_field(),
						e_y.value_field(),
						e_z.value_field(),
					);

					// Double `e`
					let (e_x3, e_y3, e_z3) =
						double_value(e_x.value_field(), e_y.value_field(), e_z.value_field());

					let (r_x_next, r_y_next, r_z_next) = if self.value_bits[i] == Fr::one() {
						(r_x3, r_y3, r_z3)
					} else {
						(r_x.value_field(), r_y.value_field(), r_z.value_field())
					};

					r_x = region.assign_advice(
						|| "r_x",
						config.r_x,
						i + 1,
						|| r_x_next.evaluate(),
					)?;
					r_y = region.assign_advice(
						|| "r_y",
						config.r_y,
						i + 1,
						|| r_y_next.evaluate(),
					)?;
					r_z = region.assign_advice(
						|| "r_z",
						config.r_z,
						i + 1,
						|| r_z_next.evaluate(),
					)?;

					e_x = region.assign_advice(|| "e_x", config.e_x, i + 1, || e_x3.evaluate())?;
					e_y = region.assign_advice(|| "e_y", config.e_y, i + 1, || e_y3.evaluate())?;
					e_z = region.assign_advice(|| "e_z", config.e_z, i + 1, || e_z3.evaluate())?;
				}

				Ok((r_x, r_y, r_z))
			},
		)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		eddsa::native::ed_on_bn254::B8,
		gadgets::bits2num::to_bits,
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
		scalar_mul: ScalarMulConfig,
		pub_ins: Column<Instance>,
		temp: Column<Advice>,
	}

	#[derive(Clone)]
	struct TestCircuit {
		r_x: Value<Fr>,
		r_y: Value<Fr>,
		r_z: Value<Fr>,
		value: Value<Fr>,
		value_bits: [Fr; 256],
	}

	impl TestCircuit {
		fn new(r_x: Fr, r_y: Fr, r_z: Fr, value: Fr) -> Self {
			Self {
				r_x: Value::known(r_x),
				r_y: Value::known(r_y),
				r_z: Value::known(r_z),
				value: Value::known(value),
				value_bits: to_bits(value.to_bytes()).map(Fr::from),
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
			let scalar_mul = ScalarMulChip::<256>::configure(meta);
			let temp = meta.advice_column();
			let instance = meta.instance_column();

			meta.enable_equality(instance);
			meta.enable_equality(temp);

			TestConfig { scalar_mul, pub_ins: instance, temp }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let (r_x, r_y, r_z, value) = layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, Fr>| {
					let r_x_assigned =
						region.assign_advice(|| "temp_x", config.temp, 0, || self.r_x)?;
					let r_y_assigned =
						region.assign_advice(|| "temp_y", config.temp, 1, || self.r_y)?;
					let r_z_assigned =
						region.assign_advice(|| "temp_z", config.temp, 2, || self.r_z)?;
					let value_assigned =
						region.assign_advice(|| "temp_value", config.temp, 3, || self.value)?;

					Ok((r_x_assigned, r_y_assigned, r_z_assigned, value_assigned))
				},
			)?;
			let scalar_mul_chip = ScalarMulChip::new(r_x, r_y, r_z, value, self.value_bits);
			let (x, y, z) = scalar_mul_chip
				.synthesize(config.scalar_mul, layouter.namespace(|| "scalar_mul"))?;
			layouter.constrain_instance(x.cell(), config.pub_ins, 0)?;
			layouter.constrain_instance(y.cell(), config.pub_ins, 1)?;
			layouter.constrain_instance(z.cell(), config.pub_ins, 2)?;
			Ok(())
		}
	}

	#[test]
	fn should_mul_point_with_scalar() {
		let scalar = Fr::from(8);
		let r = B8.projective();
		let res = B8.mul_scalar(&scalar.to_bytes());
		let circuit = TestCircuit::new(r.x, r.y, r.z, scalar);

		let k = 9;
		let pub_ins = vec![res.x, res.y, res.z];
		let prover = MockProver::run(k, &circuit, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_mul_point_with_scalar_production() {
		let scalar = Fr::from(8);
		let r = B8.projective();
		let res = B8.mul_scalar(&scalar.to_bytes());
		let circuit = TestCircuit::new(r.x, r.y, r.z, scalar);

		let k = 9;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let pub_ins = [res.x, res.y, res.z];
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[&pub_ins], rng).unwrap();

		assert!(res);
	}
}
