//! `main_gate` is a five width standard like PLONK gate that constrains the
//! equation below
//!
//! q_a * a + q_b * b + q_c * c + q_d * d + q_e * e +
//! q_mul_ab * a * b +
//! q_mul_cd * c * d +
//! public_input +
//! q_constant = 0

use halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter},
	plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Instance},
	poly::Rotation,
};
use std::marker::PhantomData;

use crate::RegionCtx;

#[derive(Copy, Clone, Debug)]
/// Configuration elements for the circuit are defined here.
pub struct MainGateConfig {
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
pub struct MainGate<F: FieldExt> {
	/// Constructs a phantom data for the FieldExt.
	_phantom: PhantomData<F>,
}

impl<F: FieldExt> MainGate<F> {
	/// Make the circuit configs.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> MainGateConfig {
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

		MainGateConfig {
			a,
			b,
			c,
			d,
			e,
			sa,
			sb,
			sc,
			sd,
			se,
			s_constant,
			s_mul_ab,
			s_mul_cd,
			instance,
		}
	}

	/// Assigns a new witness that is equal to boolean AND of `x` and `y`
	pub fn and(
		// Assigns a cell for the x.
		x: AssignedCell<F, F>,
		// Assigns a cell for the y.
		y: AssignedCell<F, F>,
		config: &MainGateConfig,
		layouter: impl Layouter<F> + Copy,
	) -> Result<AssignedCell<F, F>, Error> {
		// Both of the `x` & `y` have to be boolean.
		let x = MainGate::is_bool(x, config, layouter)?;
		let y = MainGate::is_bool(y, config, layouter)?;

		MainGate::mul(x, y, config, layouter)
	}

	/// Assigns a new witness that is either of `0` or `1`
	pub fn is_bool(
		// Assigns a cell for the x.
		x: AssignedCell<F, F>,
		config: &MainGateConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		// We should satisfy the equation below
		// (1 - x) * x = 0
		// x - x * x = 0

		// Witness layout:
		// | A   | B   | C   | D   | E  |
		// | --- | --- | --- | --- | ---|
		// | x   |     | x   | x   |    |

		layouter.assign_region(
			|| "is_bool",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);

				ctx.assign_fixed(config.sa, F::one())?;
				ctx.assign_fixed(config.s_mul_cd, -F::one())?;

				let assigned_x = ctx.assign_advice(config.a, x.value().cloned())?;
				ctx.copy_assign(config.c, assigned_x.clone())?;
				ctx.copy_assign(config.d, assigned_x.clone())?;

				Ok(assigned_x)
			},
		)
	}

	/// Assigns a new witness (`x`) that is equal to `y`
	pub fn is_equal(
		x: AssignedCell<F, F>, y: AssignedCell<F, F>, config: &MainGateConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		// We should satisfy the equation below
		// x - y = 0

		// Witness layout:
		// | A   | B   | C   | D   | E  |
		// | --- | --- | --- | --- | ---|
		// | x   | y   |  0  |     |    |

		layouter.assign_region(
			|| "is_equal",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);

				ctx.assign_fixed(config.sa, F::one())?;
				ctx.assign_fixed(config.sb, -F::one())?;

				let assigned_x = ctx.assign_advice(config.a, x.value().cloned())?;
				ctx.assign_advice(config.b, y.value().cloned())?;

				Ok(assigned_x)
			},
		)
	}

	/// Assigns a new witness that is `zero`
	pub fn is_zero(
		// Assigns a cell for the x.
		x: AssignedCell<F, F>,
		config: &MainGateConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		// We should satisfy the equation below
		// 1 - x * x_inv = 1
		// x * x_inv = 0

		// Witness layout:
		// | A   | B     | C   | D   | E  |
		// | --- | ----- | --- | --- | ---|
		// | x   | x_inv |     |     |    |

		layouter.assign_region(
			|| "is_zero",
			|region| {
				let x_inv = x.clone().value().map(|v| v.invert().unwrap_or(F::zero()));

				let mut ctx = RegionCtx::new(region, 0);

				ctx.assign_fixed(config.s_mul_ab, F::one())?;

				let assigned_x = ctx.copy_assign(config.a, x.clone())?;
				ctx.assign_advice(config.b, x_inv)?;

				Ok(assigned_x)
			},
		)
	}

	/// Assigns a new witness that is the product of `x` and `y`
	pub fn mul(
		// Assigns a cell for the x.
		x: AssignedCell<F, F>,
		// Assigns a cell for the y.
		y: AssignedCell<F, F>,
		config: &MainGateConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		// We should satisfy the equation below
		// x * y - res = 0

		// Witness layout:
		// | A   | B   | C   | D   | E  |
		// | --- | --- | --- | --- | ---|
		// | x   | y   | res |     |    |

		layouter.assign_region(
			|| "mul",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);

				ctx.assign_fixed(config.s_mul_ab, F::one())?;
				ctx.assign_fixed(config.sc, -F::one())?;

				let assigned_x = ctx.assign_advice(config.a, x.value().cloned())?;
				let assigned_y = ctx.assign_advice(config.b, y.value().cloned())?;

				let prod = assigned_x.value().cloned() * assigned_y.value();
				let assigned_prod = ctx.assign_advice(config.c, prod)?;

				Ok(assigned_prod)
			},
		)
	}

	/// Assigns a new witness that is sum of `x` and `y`
	pub fn add(
		// Assigns a cell for the x.
		x: AssignedCell<F, F>,
		// Assigns a cell for the y.
		y: AssignedCell<F, F>,
		config: &MainGateConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		// We should satisfy the equation below
		// x + y - res = 0

		// Witness layout:
		// | A   | B   | C   | D   | E  |
		// | --- | --- | --- | --- | ---|
		// | x   | y   | res |     |    |

		layouter.assign_region(
			|| "add",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);

				ctx.assign_fixed(config.sa, F::one())?;
				ctx.assign_fixed(config.sb, F::one())?;
				ctx.assign_fixed(config.sc, -F::one())?;

				let assigned_x = ctx.assign_advice(config.a, x.value().cloned())?;
				let assigned_y = ctx.assign_advice(config.b, y.value().cloned())?;

				let sum = assigned_x.value().cloned() + assigned_y.value();
				let assigned_sum = ctx.assign_advice(config.c, sum)?;

				Ok(assigned_sum)
			},
		)
	}

	/// Assigns new witness that equals to `x` if `bit` is true or assigned to
	/// `y` if `bit` is false
	pub fn select(
		// Assigns a cell for the bit.
		bit: AssignedCell<F, F>,
		// Assigns a cell for the x.
		x: AssignedCell<F, F>,
		// Assigns a cell for the y.
		y: AssignedCell<F, F>,
		config: &MainGateConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		// We should satisfy the equation below with bit asserted condition flag
		// c (x-y) + y - res = 0
		// cond * x - cond * y + y - res = 0

		// Witness layout:
		// | A   | B   | C | D   | E  |
		// | --- | --- | - | --- | ---|
		// | c   | x   | c | y   | res|

		let res = x.value().zip(y.value()).zip(bit.value()).map(|((x, y), bit)| {
			if *bit == F::one() {
				*x
			} else {
				assert_eq!(*bit, F::zero());
				*y
			}
		});

		layouter.assign_region(
			|| "select",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);

				ctx.assign_fixed(config.s_mul_ab, F::one())?;
				ctx.assign_fixed(config.s_mul_cd, -F::one())?;
				ctx.assign_fixed(config.sd, F::one())?;
				ctx.assign_fixed(config.se, -F::one())?;

				let b1 = ctx.assign_advice(config.a, bit.value().cloned())?;
				ctx.assign_advice(config.b, x.value().cloned())?;
				let b2 = ctx.assign_advice(config.c, bit.value().cloned())?;
				ctx.assign_advice(config.d, y.value().cloned())?;
				let res = ctx.assign_advice(config.e, res)?;

				ctx.constrain_equal(b1, b2)?;

				Ok(res)
			},
		)
	}
}
