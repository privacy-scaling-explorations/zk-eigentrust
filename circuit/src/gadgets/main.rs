//! `main_gate` is a five width stardart like PLONK gate that constrains the
//! equation below
//!
//! q_a * a + q_b * b + q_c * c + q_d * d + q_e * e +
//! q_mul_ab * a * b +
//! q_mul_cd * c * d +
//! public_input +
//! q_constant = 0

use halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector},
	poly::Rotation,
};
use std::marker::PhantomData;

const WIDTH: usize = 5;

#[derive(Copy, Clone, Debug)]
/// Configuration elements for the circuit are defined here.
pub struct MainConfig {
	/// Configures columns for the advice.
	a: Column<Advice>,
	b: Column<Advice>,
	c: Column<Advice>,
	d: Column<Advice>,
	e: Column<Advice>,

	/// Configures the fixed boolean values for each row of the circuit.
	sa: Column<Fixed>,
	sb: Column<Fixed>,
	sc: Column<Fixed>,
	sd: Column<Fixed>,
	se: Column<Fixed>,

	s_mul_ab: Column<Fixed>,
	s_mul_cd: Column<Fixed>,

	s_constant: Column<Fixed>,
	instance: Column<Instance>,
}

/// Structure for the main chip.
pub struct MainChip<F: FieldExt> {
	/// Constructs a phantom data for the FieldExt.
	_phantom: PhantomData<F>,
}

impl<F: FieldExt> MainChip<F> {
	/// Make the circuit configs.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> MainConfig {
		let a = meta.advice_column();
		let b = meta.advice_column();
		let c = meta.advice_column();
		let d = meta.advice_column();
		let e = meta.advice_column();

		let sa = meta.fixed_column();
		let sb = meta.fixed_column();
		let sc = meta.fixed_column();
		let sd = meta.fixed_column();
		let se = meta.fixed_column();

		let s_mul_ab = meta.fixed_column();
		let s_mul_cd = meta.fixed_column();

		let s_constant = meta.fixed_column();

		let instance = meta.instance_column();

		meta.enable_equality(a);
		meta.enable_equality(b);
		meta.enable_equality(c);
		meta.enable_equality(d);
		meta.enable_equality(e);
		meta.enable_equality(instance);

		meta.create_gate("main_gate", |meta| {
			let a = meta.query_advice(a, Rotation::cur());
			let b = meta.query_advice(b, Rotation::cur());
			let c = meta.query_advice(c, Rotation::cur());
			let d = meta.query_advice(d, Rotation::cur());
			let e = meta.query_advice(e, Rotation::cur());

			let sa = meta.query_fixed(sa, Rotation::cur());
			let sb = meta.query_fixed(sb, Rotation::cur());
			let sc = meta.query_fixed(sc, Rotation::cur());
			let sd = meta.query_fixed(sd, Rotation::cur());
			let se = meta.query_fixed(se, Rotation::cur());

			let s_mul_ab = meta.query_fixed(s_mul_ab, Rotation::cur());
			let s_mul_cd = meta.query_fixed(s_mul_cd, Rotation::cur());

			let s_constant = meta.query_fixed(s_constant, Rotation::cur());

			vec![
				a.clone() * sa
					+ b.clone() * sb + c.clone() * sc
					+ d.clone() * sd + e * se
					+ a * b * s_mul_ab + c * d * s_mul_cd
					+ s_constant,
			]
		});

		MainConfig { a, b, c, d, e, sa, sb, sc, sd, se, s_constant, s_mul_ab, s_mul_cd, instance }
	}

	// /// Synthesize the and circuit.
	// pub fn and(
	// 	// Assigns a cell for the x.
	// 	x: AssignedCell<F, F>,
	// 	// Assigns a cell for the y.
	// 	y: AssignedCell<F, F>,
	// 	config: &MainConfig,
	// 	mut layouter: impl Layouter<F>,
	// ) -> Result<AssignedCell<F, F>, Error> {
	// 	// Both of the `x` & `y` have to be boolean.
	// 	layouter.assign_region(
	// 		|| "and",
	// 		|mut region: Region<'_, F>| {
	// 			config.s_mul.enable(&mut region, 0)?;
	// 			config.s_is_bool_a.enable(&mut region, 0)?;
	// 			config.s_is_bool_b.enable(&mut region, 0)?;

	// 			config.s_c.enable(&mut region, 0)?;

	// 			let assigned_x = x.copy_advice(|| "x", &mut region, config.a, 0)?;
	// 			let assigned_y = y.copy_advice(|| "y", &mut region, config.b, 0)?;

	// 			let res = assigned_x.value().cloned() * assigned_y.value();
	// 			let res_assigned = region.assign_advice(|| "res", config.c, 0, || res)?;

	// 			Ok(res_assigned)
	// 		},
	// 	)
	// }

	// /// Synthesize the is_bool circuit.
	// pub fn is_bool(
	// 	// Assigns a cell for the x.
	// 	x: AssignedCell<F, F>,
	// 	config: &MainConfig,
	// 	mut layouter: impl Layouter<F>,
	// ) -> Result<AssignedCell<F, F>, Error> {
	// 	layouter.assign_region(
	// 		|| "is_boolean",
	// 		|mut region: Region<'_, F>| {
	// 			config.s_is_bool_a.enable(&mut region, 0)?;

	// 			let assigned_x = x.copy_advice(|| "x", &mut region, config.a, 0)?;

	// 			Ok(assigned_x)
	// 		},
	// 	)
	// }

	// /// Synthesize the is_equal circuit.
	// pub fn is_equal(
	// 	v1: AssignedCell<F, F>, v2: AssignedCell<F, F>, config: &MainConfig,
	// 	mut layouter: impl Layouter<F>,
	// ) -> Result<AssignedCell<F, F>, Error> {
	// 	layouter.assign_region(
	// 		|| "is_equal",
	// 		|mut region: Region<'_, F>| {
	// 			config.s_a.enable(&mut region, 0)?;
	// 			config.s_b.enable(&mut region, 0)?;
	// 			config.s_c.enable(&mut region, 0)?;

	// 			// Check if 0 + lhs = rhs
	// 			let out =
	// 				region.assign_advice(|| "out", config.a, 0, || Value::known(F::zero()))?;
	// 			v1.copy_advice(|| "lhs", &mut region, config.b, 0)?;
	// 			v2.copy_advice(|| "rhs", &mut region, config.c, 0)?;

	// 			Ok(out) // TODO: Should be `F::one()` ???
	// 		},
	// 	)
	// }

	// /// Synthesize the is_zero circuit.
	// pub fn is_zero(
	// 	// Assigns a cell for the x.
	// 	x: AssignedCell<F, F>,
	// 	config: &MainConfig,
	// 	mut layouter: impl Layouter<F>,
	// ) -> Result<AssignedCell<F, F>, Error> {
	// 	let is_zero = layouter.assign_region(
	// 		|| "is_zero",
	// 		|mut region: Region<'_, F>| {
	// 			config.s_mul.enable(&mut region, 0)?;
	// 			config.s_c.enable(&mut region, 0)?;

	// 			let one = Value::known(F::one());
	// 			let x_inv = x.value().and_then(|val| {
	// 				let val_opt: Option<F> = val.invert().into();
	// 				Value::known(val_opt.unwrap_or(F::one()))
	// 			});
	// 			// In the circuit here, if x = 0, b will be assigned to the value 1.
	// 			// If x = 1, means x_inv = 1 as well, b will be assigned to the value 0.
	// 			let b = one - x.value().cloned() * x_inv;

	// 			x.copy_advice(|| "x", &mut region, config.a, 0)?;
	// 			let assigned_b = region.assign_advice(|| "1 - x * x_inv", config.b, 0, ||
	// b)?; 			region.assign_advice(|| "0", config.c, 0, || Value::known(F::zero()))?;

	// 			Ok(assigned_b)
	// 		},
	// 	)?;

	// 	Ok(is_zero)
	// }

	// /// Synthesize the mul circuit.
	// pub fn mul(
	// 	// Assigns a cell for the x.
	// 	x: AssignedCell<F, F>,
	// 	// Assigns a cell for the y.
	// 	y: AssignedCell<F, F>,
	// 	config: &MainConfig,
	// 	mut layouter: impl Layouter<F>,
	// ) -> Result<AssignedCell<F, F>, Error> {
	// 	layouter.assign_region(
	// 		|| "mul",
	// 		|mut region: Region<'_, F>| {
	// 			config.s_mul.enable(&mut region, 0)?;
	// 			config.s_c.enable(&mut region, 0)?;

	// 			let assigned_x = x.copy_advice(|| "a", &mut region, config.a, 0)?;
	// 			let assigned_y = y.copy_advice(|| "b", &mut region, config.b, 0)?;

	// 			let out = assigned_x.value().cloned() * assigned_y.value();
	// 			let out_assigned = region.assign_advice(|| "a * b", config.c, 0, || out)?;

	// 			Ok(out_assigned)
	// 		},
	// 	)
	// }

	// /// Synthesize the add circuit.
	// pub fn add(
	// 	// Assigns a cell for the x.
	// 	x: AssignedCell<F, F>,
	// 	// Assigns a cell for the y.
	// 	y: AssignedCell<F, F>,
	// 	config: &MainConfig,
	// 	mut layouter: impl Layouter<F>,
	// ) -> Result<AssignedCell<F, F>, Error> {
	// 	layouter.assign_region(
	// 		|| "add",
	// 		|mut region: Region<'_, F>| {
	// 			config.s_a.enable(&mut region, 0)?;
	// 			config.s_b.enable(&mut region, 0)?;
	// 			config.s_c.enable(&mut region, 0)?;

	// 			let assigned_x = x.copy_advice(|| "a", &mut region, config.a, 0)?;
	// 			let assigned_y = y.copy_advice(|| "b", &mut region, config.b, 0)?;

	// 			let out = assigned_x.value().cloned() + assigned_y.value();
	// 			let out_assigned = region.assign_advice(|| "a + b", config.c, 0, || out)?;

	// 			Ok(out_assigned)
	// 		},
	// 	)
	// }

	// /// Synthesize the select circuit.
	// pub fn select(
	// 	// Assigns a cell for the bit.
	// 	bit: AssignedCell<F, F>,
	// 	// Assigns a cell for the x.
	// 	x: AssignedCell<F, F>,
	// 	// Assigns a cell for the y.
	// 	y: AssignedCell<F, F>,
	// 	config: &MainConfig,
	// 	mut layouter: impl Layouter<F>,
	// ) -> Result<AssignedCell<F, F>, Error> {
	// 	// Checking bit is boolean or not.
	// 	let assigned_bool = Self::is_bool(bit, config, layouter.namespace(||
	// "is_boolean"))?;

	// 	layouter.assign_region(
	// 		|| "select",
	// 		|mut region: Region<'_, F>| {
	// 			config.s_select.enable(&mut region, 0)?;

	// 			let assigned_bit = assigned_bool.copy_advice(|| "bit", &mut region, config.a,
	// 0)?; 			let assigned_x = x.copy_advice(|| "x", &mut region, config.b, 0)?;
	// 			let assigned_y = y.copy_advice(|| "y", &mut region, config.c, 0)?;

	// 			// Conditional control checks the bit. Is it zero or not?
	// 			// If yes returns the y value, else x.
	// 			let res = assigned_bit.value().and_then(|bit_f| {
	// 				if bool::from(bit_f.is_zero()) {
	// 					assigned_y.value().cloned()
	// 				} else {
	// 					assigned_x.value().cloned()
	// 				}
	// 			});

	// 			let assigned_res = region.assign_advice(|| "res", config.b, 1, || res)?;

	// 			Ok(assigned_res)
	// 		},
	// 	)
	// }
}
