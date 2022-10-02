use super::native::ops::{add_exp, add_value, double_exp, double_value};
use crate::gadgets::bits2num::{Bits2NumChip, Bits2NumConfig};
use halo2wrong::{
	curves::bn256::Fr,
	halo2::{
		circuit::{AssignedCell, Layouter, Region},
		plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
		poly::Rotation,
	},
};

#[derive(Clone)]
/// Configuration elements for the circuit are defined here.
pub struct EddsaGadgetsConfig {
	/// Constructs bits2num circuit elements.
	bits2num: Bits2NumConfig,
	/// Configures columns for the eddsa advice.
	eddsa_advice: [Column<Advice>; 7],
	/// Configures fixed boolean values for each row of the circuit.
	selectors: [Selector; 3],
}

/// Structure for the chip.
pub struct EddsaGadgetsChip;

impl EddsaGadgetsChip {
	/// Configuration for the common eddsa circuits.
	pub fn configure(meta: &mut ConstraintSystem<Fr>) -> EddsaGadgetsConfig {
		let bits2num = Bits2NumChip::<_, 256>::configure(meta);
		let eddsa_advice = [
			meta.advice_column(),
			meta.advice_column(),
			meta.advice_column(),
			meta.advice_column(),
			meta.advice_column(),
			meta.advice_column(),
			meta.advice_column(),
		];
		let selectors = [meta.selector(), meta.selector(), meta.selector()];

		eddsa_advice.map(|c| meta.enable_equality(c));

		meta.create_gate("point_add", |v_cells| {
			let s_exp = v_cells.query_selector(selectors[0]);

			let r_x_exp = v_cells.query_advice(eddsa_advice[0], Rotation::cur());
			let r_y_exp = v_cells.query_advice(eddsa_advice[1], Rotation::cur());
			let r_z_exp = v_cells.query_advice(eddsa_advice[2], Rotation::cur());

			let e_x_exp = v_cells.query_advice(eddsa_advice[3], Rotation::cur());
			let e_y_exp = v_cells.query_advice(eddsa_advice[4], Rotation::cur());
			let e_z_exp = v_cells.query_advice(eddsa_advice[5], Rotation::cur());

			let r_x_next_exp = v_cells.query_advice(eddsa_advice[0], Rotation::next());
			let r_y_next_exp = v_cells.query_advice(eddsa_advice[1], Rotation::next());
			let r_z_next_exp = v_cells.query_advice(eddsa_advice[2], Rotation::next());

			let (r_x3, r_y3, r_z3) = add_exp(
				r_x_exp.clone(),
				r_y_exp.clone(),
				r_z_exp.clone(),
				e_x_exp.clone(),
				e_y_exp.clone(),
				e_z_exp.clone(),
			);

			vec![
				// Ensure the point addition of `r` and `e` is properly calculated.
				s_exp.clone() * (r_x_next_exp - r_x3),
				s_exp.clone() * (r_y_next_exp - r_y3),
				s_exp.clone() * (r_z_next_exp - r_z3),
			]
		});

		meta.create_gate("into_affine", |v_cells| {
			let s_exp = v_cells.query_selector(selectors[1]);

			let one = Expression::Constant(Fr::one());
			let r_x_exp = v_cells.query_advice(eddsa_advice[0], Rotation::cur());
			let r_y_exp = v_cells.query_advice(eddsa_advice[1], Rotation::cur());
			let r_z_exp = v_cells.query_advice(eddsa_advice[2], Rotation::cur());

			let r_x_affine_exp = v_cells.query_advice(eddsa_advice[3], Rotation::cur());
			let r_y_affine_exp = v_cells.query_advice(eddsa_advice[4], Rotation::cur());
			let r_z_invert_exp = v_cells.query_advice(eddsa_advice[5], Rotation::cur());

			let affine_x = r_x_exp * r_z_invert_exp.clone();
			let affine_y = r_y_exp * r_z_invert_exp.clone();

			vec![
				// Ensure the affine representation is properly calculated.
				s_exp.clone() * (r_x_affine_exp - affine_x),
				s_exp.clone() * (r_y_affine_exp - affine_y),
				s_exp * (r_z_exp * r_z_invert_exp - one),
			]
		});

		meta.create_gate("scalar_mul", |v_cells| {
			let s_exp = v_cells.query_selector(selectors[2]);
			let bit_exp = v_cells.query_advice(eddsa_advice[0], Rotation::cur());

			let r_x_exp = v_cells.query_advice(eddsa_advice[1], Rotation::cur());
			let r_y_exp = v_cells.query_advice(eddsa_advice[2], Rotation::cur());
			let r_z_exp = v_cells.query_advice(eddsa_advice[3], Rotation::cur());

			let e_x_exp = v_cells.query_advice(eddsa_advice[4], Rotation::cur());
			let e_y_exp = v_cells.query_advice(eddsa_advice[5], Rotation::cur());
			let e_z_exp = v_cells.query_advice(eddsa_advice[6], Rotation::cur());

			let r_x_next_exp = v_cells.query_advice(eddsa_advice[1], Rotation::next());
			let r_y_next_exp = v_cells.query_advice(eddsa_advice[2], Rotation::next());
			let r_z_next_exp = v_cells.query_advice(eddsa_advice[3], Rotation::next());

			let e_x_next_exp = v_cells.query_advice(eddsa_advice[4], Rotation::next());
			let e_y_next_exp = v_cells.query_advice(eddsa_advice[5], Rotation::next());
			let e_z_next_exp = v_cells.query_advice(eddsa_advice[6], Rotation::next());

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
				// Ensure the point addition of `r` and `e` is properly calculated.
				s_exp.clone() * selected_r_x,
				s_exp.clone() * selected_r_y,
				s_exp.clone() * selected_r_z,
				// Ensure the `e` doubling is properly calculated.
				s_exp.clone() * (e_x_next_exp - e_x3),
				s_exp.clone() * (e_y_next_exp - e_y3),
				s_exp * (e_z_next_exp - e_z3),
			]
		});

		EddsaGadgetsConfig { bits2num, eddsa_advice, selectors }
	}

	/// Synthesize the add_point circuit.
	pub fn add_point(
		// Assigns a cell for the r_x.
		r_x: AssignedCell<Fr, Fr>,
		// Assigns a cell for the r_y.
		r_y: AssignedCell<Fr, Fr>,
		// Assigns a cell for the r_z.
		r_z: AssignedCell<Fr, Fr>,
		// Assigns a cell for the e_x.
		e_x: AssignedCell<Fr, Fr>,
		// Assigns a cell for the e_y.
		e_y: AssignedCell<Fr, Fr>,
		// Assigns a cell for the e_z.
		e_z: AssignedCell<Fr, Fr>,
		config: EddsaGadgetsConfig,
		mut layouter: impl Layouter<Fr>,
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
				config.selectors[0].enable(&mut region, 0)?;

				let r_x = r_x.copy_advice(|| "r_x", &mut region, config.eddsa_advice[0], 0)?;
				let r_y = r_y.copy_advice(|| "r_y", &mut region, config.eddsa_advice[1], 0)?;
				let r_z = r_z.copy_advice(|| "r_z", &mut region, config.eddsa_advice[2], 0)?;
				let e_x = e_x.copy_advice(|| "e_x", &mut region, config.eddsa_advice[3], 0)?;
				let e_y = e_y.copy_advice(|| "e_y", &mut region, config.eddsa_advice[4], 0)?;
				let e_z = e_z.copy_advice(|| "e_z", &mut region, config.eddsa_advice[5], 0)?;

				// Add `r` and `e`.
				let (r_x3, r_y3, r_z3) = add_value(
					r_x.value_field(),
					r_y.value_field(),
					r_z.value_field(),
					e_x.value_field(),
					e_y.value_field(),
					e_z.value_field(),
				);

				let r_x_res = region.assign_advice(
					|| "r_x",
					config.eddsa_advice[0],
					1,
					|| r_x3.evaluate(),
				)?;
				let r_y_res = region.assign_advice(
					|| "r_y",
					config.eddsa_advice[1],
					1,
					|| r_y3.evaluate(),
				)?;
				let r_z_res = region.assign_advice(
					|| "r_z",
					config.eddsa_advice[2],
					1,
					|| r_z3.evaluate(),
				)?;

				Ok((r_x_res, r_y_res, r_z_res))
			},
		)
	}

	/// Synthesize the into_affine circuit.
	pub fn into_affine(
		// Assigns a cell for the r_x.
		r_x: AssignedCell<Fr, Fr>,
		// Assigns a cell for the r_y.
		r_y: AssignedCell<Fr, Fr>,
		// Assigns a cell for the r_z.
		r_z: AssignedCell<Fr, Fr>,
		config: EddsaGadgetsConfig,
		mut layouter: impl Layouter<Fr>,
	) -> Result<(AssignedCell<Fr, Fr>, AssignedCell<Fr, Fr>), Error> {
		layouter.assign_region(
			|| "into_affine",
			|mut region: Region<'_, Fr>| {
				config.selectors[1].enable(&mut region, 0)?;

				r_x.copy_advice(|| "r_x", &mut region, config.eddsa_advice[0], 0)?;
				r_y.copy_advice(|| "r_y", &mut region, config.eddsa_advice[1], 0)?;
				r_z.copy_advice(|| "r_z", &mut region, config.eddsa_advice[2], 0)?;

				// Calculating affine representation for the point.
				// Divide both points with the third dimension to get the affine point.
				// Shrinking a line to a dot is why some projective
				// space coordinates returns to the same affine points.
				let z_invert = r_z.value_field().invert();
				let r_x_affine = r_x.value_field() * z_invert;
				let r_y_affine = r_y.value_field() * z_invert;

				let x = region.assign_advice(
					|| "r_x_affine",
					config.eddsa_advice[3],
					0,
					|| r_x_affine.evaluate(),
				)?;
				let y = region.assign_advice(
					|| "r_y_affine",
					config.eddsa_advice[4],
					0,
					|| r_y_affine.evaluate(),
				)?;
				region.assign_advice(
					|| "r_z_invert",
					config.eddsa_advice[5],
					0,
					|| z_invert.evaluate(),
				)?;

				Ok((x, y))
			},
		)
	}

	/// Synthesize the scalar_mul circuit.
	pub fn scalar_mul<const B: usize>(
		// Assigns a cell for the e_x.
		e_x: AssignedCell<Fr, Fr>,
		// Assigns a cell for the e_y.
		e_y: AssignedCell<Fr, Fr>,
		// Assigns a cell for the e_z.
		e_z: AssignedCell<Fr, Fr>,
		// Assigns a cell for the value.
		value: AssignedCell<Fr, Fr>,
		// Constructs an array for the value bits.
		value_bits: [Fr; B],
		config: EddsaGadgetsConfig,
		mut layouter: impl Layouter<Fr>,
	) -> Result<
		(
			AssignedCell<Fr, Fr>,
			AssignedCell<Fr, Fr>,
			AssignedCell<Fr, Fr>,
		),
		Error,
	> {
		let bits2num = Bits2NumChip::new(value.clone(), value_bits);
		let bits = bits2num.synthesize(config.bits2num, layouter.namespace(|| "bits2num"))?;

		layouter.assign_region(
			|| "scalar_mul",
			|mut region: Region<'_, Fr>| {
				for i in 0..bits.len() {
					bits[i].copy_advice(|| "bit", &mut region, config.eddsa_advice[0], i)?;
				}

				let mut r_x = region.assign_advice_from_constant(
					|| "r_x_0",
					config.eddsa_advice[1],
					0,
					Fr::zero(),
				)?;
				let mut r_y = region.assign_advice_from_constant(
					|| "r_y_0",
					config.eddsa_advice[2],
					0,
					Fr::one(),
				)?;
				let mut r_z = region.assign_advice_from_constant(
					|| "r_z_0",
					config.eddsa_advice[3],
					0,
					Fr::one(),
				)?;

				let mut e_x = e_x.copy_advice(|| "e_x", &mut region, config.eddsa_advice[4], 0)?;
				let mut e_y = e_y.copy_advice(|| "e_y", &mut region, config.eddsa_advice[5], 0)?;
				let mut e_z = e_z.copy_advice(|| "e_z", &mut region, config.eddsa_advice[6], 0)?;

				// Double and add operation.
				for i in 0..value_bits.len() {
					config.selectors[2].enable(&mut region, i)?;

					// Add `r` and `e`.
					let (r_x3, r_y3, r_z3) = add_value(
						r_x.value_field(),
						r_y.value_field(),
						r_z.value_field(),
						e_x.value_field(),
						e_y.value_field(),
						e_z.value_field(),
					);

					// Double `e`.
					let (e_x3, e_y3, e_z3) =
						double_value(e_x.value_field(), e_y.value_field(), e_z.value_field());

					let (r_x_next, r_y_next, r_z_next) = if value_bits[i] == Fr::one() {
						(r_x3, r_y3, r_z3)
					} else {
						(r_x.value_field(), r_y.value_field(), r_z.value_field())
					};

					r_x = region.assign_advice(
						|| "r_x",
						config.eddsa_advice[1],
						i + 1,
						|| r_x_next.evaluate(),
					)?;
					r_y = region.assign_advice(
						|| "r_y",
						config.eddsa_advice[2],
						i + 1,
						|| r_y_next.evaluate(),
					)?;
					r_z = region.assign_advice(
						|| "r_z",
						config.eddsa_advice[3],
						i + 1,
						|| r_z_next.evaluate(),
					)?;

					e_x = region.assign_advice(
						|| "e_x",
						config.eddsa_advice[4],
						i + 1,
						|| e_x3.evaluate(),
					)?;
					e_y = region.assign_advice(
						|| "e_y",
						config.eddsa_advice[5],
						i + 1,
						|| e_y3.evaluate(),
					)?;
					e_z = region.assign_advice(
						|| "e_z",
						config.eddsa_advice[6],
						i + 1,
						|| e_z3.evaluate(),
					)?;
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
		eddsa::native::{
			ed_on_bn254::{B8, G},
			ops::add,
		},
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
	enum Gadgets {
		AddPoint,
		IntoAffine,
		ScalarMul,
	}

	#[derive(Clone)]
	struct TestConfig {
		eddsa_gadgets: EddsaGadgetsConfig,
		pub_ins: Column<Instance>,
		temp: Column<Advice>,
	}

	#[derive(Clone)]
	struct TestCircuit<const N: usize> {
		inputs: [Fr; N],
		gadget: Gadgets,
	}

	impl<const N: usize> TestCircuit<N> {
		fn new(inputs: [Fr; N], gadget: Gadgets) -> Self {
			Self { inputs, gadget }
		}
	}

	impl<const N: usize> Circuit<Fr> for TestCircuit<N> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			let eddsa_gadgets = EddsaGadgetsChip::configure(meta);
			let pub_ins = meta.instance_column();
			let temp = meta.advice_column();

			meta.enable_equality(pub_ins);
			meta.enable_equality(temp);

			TestConfig { eddsa_gadgets, pub_ins, temp }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let mut items = Vec::new();
			for i in 0..N {
				items.push(layouter.assign_region(
					|| "temp",
					|mut region: Region<'_, Fr>| {
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
				Gadgets::AddPoint => {
					let (x, y, z) = EddsaGadgetsChip::add_point(
						items[0].clone(),
						items[1].clone(),
						items[2].clone(),
						items[3].clone(),
						items[4].clone(),
						items[5].clone(),
						config.eddsa_gadgets,
						layouter.namespace(|| "add"),
					)?;
					layouter.constrain_instance(x.cell(), config.pub_ins, 0)?;
					layouter.constrain_instance(y.cell(), config.pub_ins, 1)?;
					layouter.constrain_instance(z.cell(), config.pub_ins, 2)?;
				},
				Gadgets::IntoAffine => {
					let (x, y) = EddsaGadgetsChip::into_affine(
						items[0].clone(),
						items[1].clone(),
						items[2].clone(),
						config.eddsa_gadgets,
						layouter.namespace(|| "into_affine"),
					)?;
					layouter.constrain_instance(x.cell(), config.pub_ins, 0)?;
					layouter.constrain_instance(y.cell(), config.pub_ins, 1)?;
				},
				Gadgets::ScalarMul => {
					let value_bits = to_bits::<256>(self.inputs[3].to_bytes()).map(Fr::from);
					let (x, y, z) = EddsaGadgetsChip::scalar_mul(
						items[0].clone(),
						items[1].clone(),
						items[2].clone(),
						items[3].clone(),
						value_bits,
						config.eddsa_gadgets,
						layouter.namespace(|| "scalar_mul"),
					)?;
					layouter.constrain_instance(x.cell(), config.pub_ins, 0)?;
					layouter.constrain_instance(y.cell(), config.pub_ins, 1)?;
					layouter.constrain_instance(z.cell(), config.pub_ins, 2)?;
				},
			}
			Ok(())
		}
	}

	// TEST CASES FOR THE ADD_POINT CIRCUIT
	#[test]
	fn should_add_point() {
		// Testing a valid case.
		let r = B8.projective();
		let e = G.projective();
		let (x_res, y_res, z_res) = add(r.x, r.y, r.z, e.x, e.y, e.z);
		let circuit = TestCircuit::new([r.x, r.y, r.z, e.x, e.y, e.z], Gadgets::AddPoint);

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
		let circuit = TestCircuit::new([r.x, r.y, r.z, e.x, e.y, e.z], Gadgets::AddPoint);

		let k = 9;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let pub_ins = [x_res, y_res, z_res];
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[&pub_ins], rng).unwrap();

		assert!(res);
	}

	// TEST CASES FOR THE INTO_AFFINE CIRCUIT
	#[test]
	fn should_into_affine_point() {
		// Testing a valid case.
		let r = B8.projective();
		let r_affine = r.affine();
		let circuit = TestCircuit::new([r.x, r.y, r.z], Gadgets::IntoAffine);

		let k = 7;
		let pub_ins = vec![r_affine.x, r_affine.y];
		let prover = MockProver::run(k, &circuit, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_into_affine_point_production() {
		let r = B8.projective();
		let r_affine = r.affine();
		let circuit = TestCircuit::new([r.x, r.y, r.z], Gadgets::IntoAffine);

		let k = 9;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let pub_ins = vec![r_affine.x, r_affine.y];
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[&pub_ins], rng).unwrap();

		assert!(res);
	}

	//TEST CASES FOR THE SCALAR_MUL CIRCUIT
	#[test]
	fn should_mul_point_with_scalar() {
		// Testing scalar as value 8.
		let scalar = Fr::from(8);
		let r = B8.projective();
		let res = B8.mul_scalar(&scalar.to_bytes());
		let circuit = TestCircuit::new([r.x, r.y, r.z, scalar], Gadgets::ScalarMul);

		let k = 9;
		let pub_ins = vec![res.x, res.y, res.z];
		let prover = MockProver::run(k, &circuit, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_scalar_mul_zero() {
		// Testing scalar as value 0.
		let scalar = Fr::from(0);
		let r = B8.projective();
		let res = B8.mul_scalar(&scalar.to_bytes());
		let circuit = TestCircuit::new([r.x, r.y, r.z, scalar], Gadgets::ScalarMul);

		let k = 9;
		let pub_ins = vec![res.x, res.y, res.z];
		let prover = MockProver::run(k, &circuit, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_scalar_mul_one() {
		// Testing scalar as value 1.
		let scalar = Fr::from(1);
		let r = B8.projective();
		let res = B8.mul_scalar(&scalar.to_bytes());
		let circuit = TestCircuit::new([r.x, r.y, r.z, scalar], Gadgets::ScalarMul);

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
		let circuit = TestCircuit::new([r.x, r.y, r.z, scalar], Gadgets::ScalarMul);

		let k = 9;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let pub_ins = [res.x, res.y, res.z];
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[&pub_ins], rng).unwrap();

		assert!(res);
	}
}
