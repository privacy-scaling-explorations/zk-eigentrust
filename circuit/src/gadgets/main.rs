use halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};
use std::marker::PhantomData;

#[derive(Copy, Clone, Debug)]
/// Configuration elements for the circuit are defined here.
pub struct MainConfig {
	/// Configures columns for the advice.
	a: Column<Advice>,
	b: Column<Advice>,
	c: Column<Advice>,

	/// Configures the fixed boolean values for each row of the circuit.
	s_a: Selector,
	s_b: Selector,
	s_mul: Selector,
	s_c: Selector,

	s_is_bool_a: Selector,
	s_is_bool_b: Selector,
	s_select: Selector,
}

/// Structure for the main chip.
pub struct MainChip<F: FieldExt> {
	/// Constructs a phantom data for the FieldExt.
	_phantom: PhantomData<F>,
}

impl<F: FieldExt> MainChip<F> {
	/// Make the circuit configs.
	pub fn configure(meta: &mut ConstraintSystem<F>, advices: [Column<Advice>; 3]) -> MainConfig {
		let [a, b, c] = advices;

		let s_a = meta.complex_selector();
		let s_b = meta.complex_selector();
		let s_c = meta.complex_selector();

		let s_mul = meta.complex_selector();
		let s_is_bool_a = meta.complex_selector();
		let s_is_bool_b = meta.complex_selector();
		let s_select = meta.complex_selector();

		meta.enable_equality(a);
		meta.enable_equality(b);
		meta.enable_equality(c);

		// Gate for the circuit.
		meta.create_gate("custom", |v_cells| {
			/*

			 //	Custom circuit

			 |  a  |  b    |  c  |  s_a  |  s_b  |  s_c  |  s_mul  | s_is_bool_a  |  s_is_bool_b  |  s_select  |   Operation  |
			 |-----|-------|-----|-------|-------|-------|---------|--------------|---------------|------------|--------------|
			 |  a  |  b    | a+b |   1   |   1   |   1   |    0    |      0       |       0       |     0      |     add      |
			 |  a  |  b    | a*b |   0   |   0   |   1   |    1    |      0       |       0       |     0      |     mul      |
			 |  a  | any   | any |   0   |   0   |   0   |    0    |      1       |       0       |     0      | is_bool (a)  |
			 | any |  b    | any |   0   |   0   |   0   |    0    |      0       |       1       |     0      | is_bool (b)  |
			 |  0  |  a    |  b  |   1   |   1   |   1   |    0    |      0       |       0       |     0      |   is_equal   |
			 |  a  |calc(a)|  0  |   0   |   0   |   1   |    1    |      0       |       0       |     0      |   is_zero    |
			 |  a  |  b    | a*b |   0   |   0   |   1   |    1    |      1       |       1       |     0      |     and      |


			 **Ref: calc(a) = 1 - a * (1/a)

			*/
			let one = Expression::Constant(F::one());

			let a = v_cells.query_advice(a, Rotation::cur());
			let b = v_cells.query_advice(b, Rotation::cur());
			let c = v_cells.query_advice(c, Rotation::cur());

			let s_a = v_cells.query_selector(s_a);
			let s_b = v_cells.query_selector(s_b);
			let s_c = v_cells.query_selector(s_c);

			let s_mul = v_cells.query_selector(s_mul);
			let s_is_bool_a = v_cells.query_selector(s_is_bool_a);
			let s_is_bool_b = v_cells.query_selector(s_is_bool_b);

			vec![
				s_mul * (a.clone() * b.clone())
					+ s_a * a.clone() + s_b * b.clone()
					+ s_is_bool_a * (one.clone() - a.clone()) * a.clone()
					+ s_is_bool_b * (one - b.clone()) * b.clone()
					+ s_c * c * (-F::one()),
			]
		});

		// Gate for the select circuit.
		meta.create_gate("select", |v_cells| {
			let bit = v_cells.query_advice(a, Rotation::cur());
			let x = v_cells.query_advice(b, Rotation::cur());
			let y = v_cells.query_advice(c, Rotation::cur());
			let z = v_cells.query_advice(b, Rotation::next());

			let s_select = v_cells.query_selector(s_select);

			vec![
				//
				//	|  a  |  b  |  c  |  s_select |
				//	|-----|-----|-----|-----------|
				//	| bit |  x  |  y  |     1     |
				//	|     |  z  |
				//
				//
				// bit * (x - y) - (z - y)
				// Example 1:
				// 	bit = 1
				// 	z will carry the same value with x when bit == 1. (x == z)
				// 	x = 5
				// 	y = 3
				// 	z = 5
				// 	1 * (x - y) - (z - y) = 1 * (5 - 3) - (5 - 3) = 0
				// Example 2:
				// 	bit = 0
				// 	z will carry the same value with y when bit == 0. (y == z)
				// 	x = 5
				// 	y = 3
				// 	z = 3
				// 	0 * (x - y) - (z - y) = 0 * (5 - 3) - (3 - 3) = 0
				s_select * (bit * (x - y.clone()) - (z - y)),
			]
		});

		MainConfig { a, b, c, s_a, s_b, s_mul, s_c, s_is_bool_a, s_is_bool_b, s_select }
	}

	/// Synthesize the and circuit.
	pub fn and(
		// Assigns a cell for the x.
		x: AssignedCell<F, F>,
		// Assigns a cell for the y.
		y: AssignedCell<F, F>,
		config: &MainConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		// Both of the `x` & `y` have to be boolean.
		layouter.assign_region(
			|| "and",
			|mut region: Region<'_, F>| {
				config.s_mul.enable(&mut region, 0)?;
				config.s_is_bool_a.enable(&mut region, 0)?;
				config.s_is_bool_b.enable(&mut region, 0)?;

				config.s_c.enable(&mut region, 0)?;

				let assigned_x = x.copy_advice(|| "x", &mut region, config.a, 0)?;
				let assigned_y = y.copy_advice(|| "y", &mut region, config.b, 0)?;

				let res = assigned_x.value().cloned() * assigned_y.value();
				let res_assigned = region.assign_advice(|| "res", config.c, 0, || res)?;

				Ok(res_assigned)
			},
		)
	}

	/// Synthesize the is_bool circuit.
	pub fn is_bool(
		// Assigns a cell for the x.
		x: AssignedCell<F, F>,
		config: &MainConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		layouter.assign_region(
			|| "is_boolean",
			|mut region: Region<'_, F>| {
				config.s_is_bool_a.enable(&mut region, 0)?;

				let assigned_x = x.copy_advice(|| "x", &mut region, config.a, 0)?;

				Ok(assigned_x)
			},
		)
	}

	/// Synthesize the is_equal circuit.
	pub fn is_equal(
		v1: AssignedCell<F, F>, v2: AssignedCell<F, F>, config: &MainConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		layouter.assign_region(
			|| "is_equal",
			|mut region: Region<'_, F>| {
				config.s_a.enable(&mut region, 0)?;
				config.s_b.enable(&mut region, 0)?;
				config.s_c.enable(&mut region, 0)?;

				// Check if 0 + lhs = rhs
				let out =
					region.assign_advice(|| "out", config.a, 0, || Value::known(F::zero()))?;
				v1.copy_advice(|| "lhs", &mut region, config.b, 0)?;
				v2.copy_advice(|| "rhs", &mut region, config.c, 0)?;

				Ok(out) // TODO: Should be `F::one()` ???
			},
		)
	}

	/// Synthesize the is_zero circuit.
	pub fn is_zero(
		// Assigns a cell for the x.
		x: AssignedCell<F, F>,
		config: &MainConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		let is_zero = layouter.assign_region(
			|| "is_zero",
			|mut region: Region<'_, F>| {
				config.s_mul.enable(&mut region, 0)?;
				config.s_c.enable(&mut region, 0)?;

				let one = Value::known(F::one());
				let x_inv = x.value().and_then(|val| {
					let val_opt: Option<F> = val.invert().into();
					Value::known(val_opt.unwrap_or(F::one()))
				});
				// In the circuit here, if x = 0, b will be assigned to the value 1.
				// If x = 1, means x_inv = 1 as well, b will be assigned to the value 0.
				let b = one - x.value().cloned() * x_inv;

				x.copy_advice(|| "x", &mut region, config.a, 0)?;
				let assigned_b = region.assign_advice(|| "1 - x * x_inv", config.b, 0, || b)?;
				region.assign_advice(|| "0", config.c, 0, || Value::known(F::zero()))?;

				Ok(assigned_b)
			},
		)?;

		Ok(is_zero)
	}

	/// Synthesize the mul circuit.
	pub fn mul(
		// Assigns a cell for the x.
		x: AssignedCell<F, F>,
		// Assigns a cell for the y.
		y: AssignedCell<F, F>,
		config: &MainConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		layouter.assign_region(
			|| "mul",
			|mut region: Region<'_, F>| {
				config.s_mul.enable(&mut region, 0)?;
				config.s_c.enable(&mut region, 0)?;

				let assigned_x = x.copy_advice(|| "a", &mut region, config.a, 0)?;
				let assigned_y = y.copy_advice(|| "b", &mut region, config.b, 0)?;

				let out = assigned_x.value().cloned() * assigned_y.value();
				let out_assigned = region.assign_advice(|| "a * b", config.c, 0, || out)?;

				Ok(out_assigned)
			},
		)
	}

	/// Synthesize the add circuit.
	pub fn add(
		// Assigns a cell for the x.
		x: AssignedCell<F, F>,
		// Assigns a cell for the y.
		y: AssignedCell<F, F>,
		config: &MainConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		layouter.assign_region(
			|| "add",
			|mut region: Region<'_, F>| {
				config.s_a.enable(&mut region, 0)?;
				config.s_b.enable(&mut region, 0)?;
				config.s_c.enable(&mut region, 0)?;

				let assigned_x = x.copy_advice(|| "a", &mut region, config.a, 0)?;
				let assigned_y = y.copy_advice(|| "b", &mut region, config.b, 0)?;

				let out = assigned_x.value().cloned() + assigned_y.value();
				let out_assigned = region.assign_advice(|| "a + b", config.c, 0, || out)?;

				Ok(out_assigned)
			},
		)
	}

	/// Synthesize the select circuit.
	pub fn select(
		// Assigns a cell for the bit.
		bit: AssignedCell<F, F>,
		// Assigns a cell for the x.
		x: AssignedCell<F, F>,
		// Assigns a cell for the y.
		y: AssignedCell<F, F>,
		config: &MainConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		// Checking bit is boolean or not.
		let assigned_bool = Self::is_bool(bit, config, layouter.namespace(|| "is_boolean"))?;

		layouter.assign_region(
			|| "select",
			|mut region: Region<'_, F>| {
				config.s_select.enable(&mut region, 0)?;

				let assigned_bit = assigned_bool.copy_advice(|| "bit", &mut region, config.a, 0)?;
				let assigned_x = x.copy_advice(|| "x", &mut region, config.b, 0)?;
				let assigned_y = y.copy_advice(|| "y", &mut region, config.c, 0)?;

				// Conditional control checks the bit. Is it zero or not?
				// If yes returns the y value, else x.
				let res = assigned_bit.value().and_then(|bit_f| {
					if bool::from(bit_f.is_zero()) {
						assigned_y.value().cloned()
					} else {
						assigned_x.value().cloned()
					}
				});

				let assigned_res = region.assign_advice(|| "res", config.b, 1, || res)?;

				Ok(assigned_res)
			},
		)
	}
}
