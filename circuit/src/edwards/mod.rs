/// Native implementation of edward curve operations
pub mod native;
/// Edward curve params
pub mod params;

use crate::{
	gadgets::bits2num::{Bits2NumChip, Bits2NumConfig},
	Chipset,
};
use halo2::{
	circuit::{AssignedCell, Layouter, Region, Value},
	halo2curves::FieldExt,
	plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};
use params::EdwardsParams;
use std::marker::PhantomData;

/// Assigned point from the circuit
pub struct AssignedPoint<F: FieldExt> {
	/// Point x
	pub x: AssignedCell<F, F>,
	/// Point y
	pub y: AssignedCell<F, F>,
	/// Point z
	pub z: AssignedCell<F, F>,
}

/// Unassigned point
pub struct UnassignedPoint<F> {
	/// Point x
	pub x: Value<F>,
	/// Point y
	pub y: Value<F>,
	/// Point z
	pub z: Value<F>,
}

impl<F: FieldExt> AssignedPoint<F> {
	/// Create a new assigned point, given the coordinates
	pub fn new(x: AssignedCell<F, F>, y: AssignedCell<F, F>, z: AssignedCell<F, F>) -> Self {
		Self { x, y, z }
	}
}

/// Structure for the eddsa gadgets chip.
pub struct PointAddChip<F: FieldExt, P: EdwardsParams<F>> {
	e: AssignedPoint<F>,
	r: AssignedPoint<F>,
	_p: PhantomData<P>,
}

impl<F: FieldExt, P: EdwardsParams<F>> PointAddChip<F, P> {
	pub fn new(e: AssignedPoint<F>, r: AssignedPoint<F>) -> Self {
		Self { e, r, _p: PhantomData }
	}
}

impl<F: FieldExt, P: EdwardsParams<F>> Chip<F> for PointAddChip<F, P> {
	type Output = AssignedPoint<F>;

	fn configure(config: CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector {
		let selector = meta.selector();

		meta.create_gate("point_add", |v_cells| {
			let s_exp = v_cells.query_selector(selector);

			let r_x_exp = v_cells.query_advice(config.advice[0], Rotation::cur());
			let r_y_exp = v_cells.query_advice(config.advice[1], Rotation::cur());
			let r_z_exp = v_cells.query_advice(config.advice[2], Rotation::cur());

			let e_x_exp = v_cells.query_advice(config.advice[3], Rotation::cur());
			let e_y_exp = v_cells.query_advice(config.advice[4], Rotation::cur());
			let e_z_exp = v_cells.query_advice(config.advice[5], Rotation::cur());

			let r_x_next_exp = v_cells.query_advice(config.advice[0], Rotation::next());
			let r_y_next_exp = v_cells.query_advice(config.advice[1], Rotation::next());
			let r_z_next_exp = v_cells.query_advice(config.advice[2], Rotation::next());

			let (r_x3, r_y3, r_z3) = P::add_exp(
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

		selector
	}

	fn synthesize(
		&self, config: CommonConfig, selector: Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		layouter.assign_region(
			|| "add",
			|mut region: Region<'_, F>| {
				config.selectors[0].enable(&mut region, 0)?;

				let r_x = r.x.copy_advice(|| "r_x", &mut region, config.advice[0], 0)?;
				let r_y = r.y.copy_advice(|| "r_y", &mut region, config.advice[1], 0)?;
				let r_z = r.z.copy_advice(|| "r_z", &mut region, config.advice[2], 0)?;
				let e_x = e.x.copy_advice(|| "e_x", &mut region, config.advice[3], 0)?;
				let e_y = e.y.copy_advice(|| "e_y", &mut region, config.advice[4], 0)?;
				let e_z = e.z.copy_advice(|| "e_z", &mut region, config.advice[5], 0)?;

				// Add `r` and `e`.
				let (r_x3, r_y3, r_z3) = P::add_value(
					r_x.value().cloned(),
					r_y.value().cloned(),
					r_z.value().cloned(),
					e_x.value().cloned(),
					e_y.value().cloned(),
					e_z.value().cloned(),
				);

				let r_x_res = region.assign_advice(|| "r_x", config.advice[0], 1, || r_x3)?;
				let r_y_res = region.assign_advice(|| "r_y", config.advice[1], 1, || r_y3)?;
				let r_z_res = region.assign_advice(|| "r_z", config.advice[2], 1, || r_z3)?;

				let res = AssignedPoint::new(r_x_res, r_y_res, r_z_res);

				Ok(res)
			},
		)
	}
}

struct IntoAffineChip<F: FieldExt> {
	r: AssignedPoint<F>,
}

impl<F: FieldExt> IntoAffineChip<F> {
	pub fn new(r: AssignedPoint<F>) -> Self {
		Self { r }
	}
}

impl<F: FieldExt> Chip<F> for IntoAffineChip<F> {
	type Output = (AssignedCell<F, F>, AssignedCell<F, F>);

	fn configure(config: CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector {
		let selector = meta.selector();

		meta.create_gate("into_affine", |v_cells| {
			let s_exp = v_cells.query_selector(selector);

			let one = Expression::Constant(F::one());
			let r_x_exp = v_cells.query_advice(config.advice[0], Rotation::cur());
			let r_y_exp = v_cells.query_advice(config.advice[1], Rotation::cur());
			let r_z_exp = v_cells.query_advice(config.advice[2], Rotation::cur());

			let r_x_affine_exp = v_cells.query_advice(config.advice[3], Rotation::cur());
			let r_y_affine_exp = v_cells.query_advice(config.advice[4], Rotation::cur());
			let r_z_invert_exp = v_cells.query_advice(config.advice[5], Rotation::cur());

			let affine_x = r_x_exp * r_z_invert_exp.clone();
			let affine_y = r_y_exp * r_z_invert_exp.clone();

			vec![
				// Ensure the affine representation is properly calculated.
				s_exp.clone() * (r_x_affine_exp - affine_x),
				s_exp.clone() * (r_y_affine_exp - affine_y),
				s_exp * (r_z_exp * r_z_invert_exp - one),
			]
		});

		selector
	}

	fn synthesize(
		&self, config: CommonConfig, selector: Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		layouter.assign_region(
			|| "into_affine",
			|mut region: Region<'_, F>| {
				config.selectors[1].enable(&mut region, 0)?;

				r.x.copy_advice(|| "r_x", &mut region, config.advice[0], 0)?;
				r.y.copy_advice(|| "r_y", &mut region, config.advice[1], 0)?;
				r.z.copy_advice(|| "r_z", &mut region, config.advice[2], 0)?;

				// Calculating affine representation for the point.
				// Divide both points with the third dimension to get the affine point.
				// Shrinking a line to a dot is why some projective
				// space coordinates returns to the same affine points.
				let z_invert = r.z.value_field().invert();
				let r_x_affine = r.x.value_field() * z_invert;
				let r_y_affine = r.y.value_field() * z_invert;

				let x = region.assign_advice(
					|| "r_x_affine",
					config.advice[3],
					0,
					|| r_x_affine.evaluate(),
				)?;
				let y = region.assign_advice(
					|| "r_y_affine",
					config.advice[4],
					0,
					|| r_y_affine.evaluate(),
				)?;
				region.assign_advice(
					|| "r_z_invert",
					config.advice[5],
					0,
					|| z_invert.evaluate(),
				)?;

				Ok((x, y))
			},
		)
	}
}

struct ScalarMulChip<F: FieldExt, const B: usize> {
	e: AssignedPoint<F>,
	// Constructs an array for the value bits.
	value_bits: [AssignedCell<F, F>; B],
}

impl<F: FieldExt, const B: usize> ScalarMulChip<F, B> {
	pub fn new(e: AssignedPoint<F>, value_bits: [AssignedCell<F, F>; B]) -> Self {
		Self { e, value_bits }
	}
}

impl<F: FieldExt, const B: usize> Chip<F> for ScalarMulChip<F, B> {
	type Output = AssignedPoint<F>;

	fn configure(config: CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector {
		let selector = meta.selector();

		meta.create_gate("scalar_mul", |v_cells| {
			let s_exp = v_cells.query_selector(selector);
			let bit_exp = v_cells.query_advice(config.advice[0], Rotation::cur());

			let r_x_exp = v_cells.query_advice(config.advice[1], Rotation::cur());
			let r_y_exp = v_cells.query_advice(config.advice[2], Rotation::cur());
			let r_z_exp = v_cells.query_advice(config.advice[3], Rotation::cur());

			let e_x_exp = v_cells.query_advice(config.advice[4], Rotation::cur());
			let e_y_exp = v_cells.query_advice(config.advice[5], Rotation::cur());
			let e_z_exp = v_cells.query_advice(config.advice[6], Rotation::cur());

			let r_x_next_exp = v_cells.query_advice(config.advice[1], Rotation::next());
			let r_y_next_exp = v_cells.query_advice(config.advice[2], Rotation::next());
			let r_z_next_exp = v_cells.query_advice(config.advice[3], Rotation::next());

			let e_x_next_exp = v_cells.query_advice(config.advice[4], Rotation::next());
			let e_y_next_exp = v_cells.query_advice(config.advice[5], Rotation::next());
			let e_z_next_exp = v_cells.query_advice(config.advice[6], Rotation::next());

			// TODO: Replace with special double_add operation
			let (r_x3, r_y3, r_z3) = P::add_exp(
				r_x_exp.clone(),
				r_y_exp.clone(),
				r_z_exp.clone(),
				e_x_exp.clone(),
				e_y_exp.clone(),
				e_z_exp.clone(),
			);

			let (e_x3, e_y3, e_z3) = P::double_exp(e_x_exp, e_y_exp, e_z_exp);

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

		selector
	}

	fn synthesize(
		&self, config: CommonConfig, selector: Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		layouter.assign_region(
			|| "scalar_mul",
			|mut region: Region<'_, F>| {
				for i in 0..bits.len() {
					bits[i].copy_advice(|| "bit", &mut region, config.advice[0], i)?;
				}

				let mut r_x = region.assign_advice_from_constant(
					|| "r_x_0",
					config.advice[1],
					0,
					F::zero(),
				)?;
				let mut r_y = region.assign_advice_from_constant(
					|| "r_y_0",
					config.advice[2],
					0,
					F::one(),
				)?;
				let mut r_z = region.assign_advice_from_constant(
					|| "r_z_0",
					config.advice[3],
					0,
					F::one(),
				)?;

				let mut e_x = e.x.copy_advice(|| "e_x", &mut region, config.advice[4], 0)?;
				let mut e_y = e.y.copy_advice(|| "e_y", &mut region, config.advice[5], 0)?;
				let mut e_z = e.z.copy_advice(|| "e_z", &mut region, config.advice[6], 0)?;

				// Double and add operation.
				for i in 0..value_bits.len() {
					config.selectors[2].enable(&mut region, i)?;

					// Add `r` and `e`.
					let (r_x3, r_y3, r_z3) = P::add_value(
						r_x.value().cloned(),
						r_y.value().cloned(),
						r_z.value().cloned(),
						e_x.value().cloned(),
						e_y.value().cloned(),
						e_z.value().cloned(),
					);

					// Double `e`.
					let (e_x3, e_y3, e_z3) = P::double_value(
						e_x.value().cloned(),
						e_y.value().cloned(),
						e_z.value().cloned(),
					);

					let (r_x_next, r_y_next, r_z_next) = if value_bits[i] == F::one() {
						(r_x3, r_y3, r_z3)
					} else {
						(
							r_x.value().cloned(),
							r_y.value().cloned(),
							r_z.value().cloned(),
						)
					};

					r_x = region.assign_advice(
						|| "r_x",
						config.eddsa_advice[1],
						i + 1,
						|| r_x_next,
					)?;
					r_y = region.assign_advice(
						|| "r_y",
						config.eddsa_advice[2],
						i + 1,
						|| r_y_next,
					)?;
					r_z = region.assign_advice(
						|| "r_z",
						config.eddsa_advice[3],
						i + 1,
						|| r_z_next,
					)?;

					e_x = region.assign_advice(|| "e_x", config.advice[4], i + 1, || e_x3)?;
					e_y = region.assign_advice(|| "e_y", config.advice[5], i + 1, || e_y3)?;
					e_z = region.assign_advice(|| "e_z", config.advice[6], i + 1, || e_z3)?;
				}

				let res = AssignedPoint::new(r_x, r_y, r_z);

				Ok(res)
			},
		)
	}
}

struct StrictScalarMulConfig {
	bits2num_selector: Selector,
	scalar_mul_selector: Selector,
}

struct StrictScalarMulChipset<F: FieldExt, const B: usize> {
	e: AssignedPoint<F>,
	value: AssignedCell<F, F>,
	value_bits: [F; B],
}

impl<F: FieldExt, const B: usize> StrictScalarMulChipset<F, B> {
	pub fn new(e: AssignedPoint<F>, value: AssignedCell<F, F>, value_bits: [F; B]) -> Self {
		Self { e, value, value_bits }
	}
}

impl<F: FieldExt, const B: usize> Chipset<F> for StrictScalarMulChipset<F, B> {
	type Config = StrictScalarMulConfig;
	type Output = AssignedPoint<F>;

	fn synthesize(
		&self, common: CommonConfig, config: Self::Config, layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		let bits2num_chip = Bits2NumChip::new(self.value, self.value_bits);
		let bits = bits2num_chip.synthesize(
			common,
			config.bits2num_selector,
			layouter.namespace(|| "scalar_bits"),
		)?;

		let scalar_chip = ScalarMulChip::new(self.e, bits);
		let res = scalar_chip.synthesize(
			common,
			config.scalar_mul_selector,
			layouter.namespace(|| "scalar_mul"),
		)?;

		Ok(res)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		edwards::{native::Point, params::BabyJubJub},
		gadgets::bits2num::to_bits,
		utils::{generate_params, prove_and_verify},
	};
	use halo2::{
		circuit::{SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::bn256::{Bn256, Fr},
		plonk::{Circuit, Instance},
	};

	#[derive(Clone)]
	enum Gadgets {
		AddPoint,
		IntoAffine,
		ScalarMul,
	}

	#[derive(Clone)]
	struct TestConfig {
		edwards: EdwardsConfig,
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
			let edwards = EdwardsChip::<Fr, BabyJubJub>::configure(meta);
			let pub_ins = meta.instance_column();
			let temp = meta.advice_column();

			meta.enable_equality(pub_ins);
			meta.enable_equality(temp);

			TestConfig { edwards, pub_ins, temp }
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
					let r =
						AssignedPoint::new(items[0].clone(), items[1].clone(), items[2].clone());
					let e =
						AssignedPoint::new(items[3].clone(), items[4].clone(), items[5].clone());
					let res = EdwardsChip::<_, BabyJubJub>::add_point(
						r,
						e,
						&config.edwards,
						layouter.namespace(|| "add"),
					)?;
					layouter.constrain_instance(res.x.cell(), config.pub_ins, 0)?;
					layouter.constrain_instance(res.y.cell(), config.pub_ins, 1)?;
					layouter.constrain_instance(res.z.cell(), config.pub_ins, 2)?;
				},
				Gadgets::IntoAffine => {
					let p =
						AssignedPoint::new(items[0].clone(), items[1].clone(), items[2].clone());
					let (x, y) = EdwardsChip::<_, BabyJubJub>::into_affine(
						p,
						&config.edwards,
						layouter.namespace(|| "into_affine"),
					)?;
					layouter.constrain_instance(x.cell(), config.pub_ins, 0)?;
					layouter.constrain_instance(y.cell(), config.pub_ins, 1)?;
				},
				Gadgets::ScalarMul => {
					let e =
						AssignedPoint::new(items[0].clone(), items[1].clone(), items[2].clone());
					let value_bits = to_bits::<256>(self.inputs[3].to_bytes()).map(Fr::from);
					let res = EdwardsChip::<_, BabyJubJub>::scalar_mul(
						e,
						items[3].clone(),
						value_bits,
						&config.edwards,
						layouter.namespace(|| "scalar_mul"),
					)?;
					layouter.constrain_instance(res.x.cell(), config.pub_ins, 0)?;
					layouter.constrain_instance(res.y.cell(), config.pub_ins, 1)?;
					layouter.constrain_instance(res.z.cell(), config.pub_ins, 2)?;
				},
			}
			Ok(())
		}
	}

	// TEST CASES FOR THE ADD_POINT CIRCUIT
	#[test]
	fn should_add_point() {
		// Testing a valid case.
		let (r_x, r_y) = BabyJubJub::b8();
		let r = Point::<Fr, BabyJubJub>::new(r_x, r_y).projective();
		let (e_x, e_y) = BabyJubJub::g();
		let e = Point::<Fr, BabyJubJub>::new(e_x, e_y).projective();
		let (x_res, y_res, z_res) = BabyJubJub::add(r.x, r.y, r.z, e.x, e.y, e.z);
		let circuit = TestCircuit::new([r.x, r.y, r.z, e.x, e.y, e.z], Gadgets::AddPoint);

		let k = 7;
		let pub_ins = vec![x_res, y_res, z_res];
		let prover = MockProver::run(k, &circuit, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_add_point_production() {
		let (r_x, r_y) = BabyJubJub::b8();
		let r = Point::<Fr, BabyJubJub>::new(r_x, r_y).projective();
		let (e_x, e_y) = BabyJubJub::g();
		let e = Point::<Fr, BabyJubJub>::new(e_x, e_y).projective();
		let (x_res, y_res, z_res) = BabyJubJub::add(r.x, r.y, r.z, e.x, e.y, e.z);
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
		let (r_x, r_y) = BabyJubJub::b8();
		let r = Point::<Fr, BabyJubJub>::new(r_x, r_y).projective();
		let r_affine = r.affine();
		let circuit = TestCircuit::new([r.x, r.y, r.z], Gadgets::IntoAffine);

		let k = 7;
		let pub_ins = vec![r_affine.x, r_affine.y];
		let prover = MockProver::run(k, &circuit, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_into_affine_point_production() {
		let (r_x, r_y) = BabyJubJub::b8();
		let r = Point::<Fr, BabyJubJub>::new(r_x, r_y).projective();
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
		let (r_x, r_y) = BabyJubJub::b8();
		let r_point = Point::<Fr, BabyJubJub>::new(r_x, r_y);
		let r = r_point.projective();
		let res = r_point.mul_scalar(&scalar.to_bytes());
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
		let (r_x, r_y) = BabyJubJub::b8();
		let r_point = Point::<Fr, BabyJubJub>::new(r_x, r_y);
		let r = r_point.projective();
		let res = r_point.mul_scalar(&scalar.to_bytes());
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
		let (r_x, r_y) = BabyJubJub::b8();
		let r_point = Point::<Fr, BabyJubJub>::new(r_x, r_y);
		let r = r_point.projective();
		let res = r_point.mul_scalar(&scalar.to_bytes());
		let circuit = TestCircuit::new([r.x, r.y, r.z, scalar], Gadgets::ScalarMul);

		let k = 9;
		let pub_ins = vec![res.x, res.y, res.z];
		let prover = MockProver::run(k, &circuit, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_mul_point_with_scalar_production() {
		let scalar = Fr::from(8);
		let (r_x, r_y) = BabyJubJub::b8();
		let r_point = Point::<Fr, BabyJubJub>::new(r_x, r_y);
		let r = r_point.projective();
		let res = r_point.mul_scalar(&scalar.to_bytes());
		let circuit = TestCircuit::new([r.x, r.y, r.z, scalar], Gadgets::ScalarMul);

		let k = 9;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let pub_ins = [res.x, res.y, res.z];
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[&pub_ins], rng).unwrap();

		assert!(res);
	}
}
