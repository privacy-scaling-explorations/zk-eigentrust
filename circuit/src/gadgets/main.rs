//! `main_gate` is a five width standard like PLONK gate that constrains the
//! equation below
//!
//! q_a * a + q_b * b + q_c * c + q_d * d + q_e * e +
//! q_mul_ab * a * b +
//! q_mul_cd * c * d +
//! public_input +
//! q_constant = 0

use crate::{Chip, Chipset, RegionCtx};
use halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
	poly::Rotation,
};

/// Number of advice columns inside the `MaingateConfig`
pub const NUM_ADVICE: usize = 5;

/// Number of fixed columns inside the `MaingateConfig`
pub const NUM_FIXED: usize = 8;

// #[derive(Copy, Clone, Debug)]
// /// Configuration elements for the circuit are defined here.
// pub struct MainGateConfig {
// 	/// Configures columns for the advice.
// 	a: Column<Advice>,
// 	b: Column<Advice>,
// 	c: Column<Advice>,
// 	d: Column<Advice>,
// 	e: Column<Advice>,

// 	/// Configures the fixed boolean values for each row of the circuit.
// 	sa: Column<Fixed>,
// 	sb: Column<Fixed>,
// 	sc: Column<Fixed>,
// 	sd: Column<Fixed>,
// 	se: Column<Fixed>,

// 	s_mul_ab: Column<Fixed>,
// 	s_mul_cd: Column<Fixed>,

// 	s_constant: Column<Fixed>,
// 	instance: Column<Instance>,
// }

// impl MainGateConfig {
// 	/// Configure the constraint of gate
// 	pub fn new<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
// 		let a = meta.advice_column();
// 		let b = meta.advice_column();
// 		let c = meta.advice_column();
// 		let d = meta.advice_column();
// 		let e = meta.advice_column();

// 		let sa = meta.fixed_column();
// 		let sb = meta.fixed_column();
// 		let sc = meta.fixed_column();
// 		let sd = meta.fixed_column();
// 		let se = meta.fixed_column();

// 		let s_mul_ab = meta.fixed_column();
// 		let s_mul_cd = meta.fixed_column();

// 		let s_constant = meta.fixed_column();

// 		let instance = meta.instance_column();

// 		meta.enable_equality(a);
// 		meta.enable_equality(b);
// 		meta.enable_equality(c);
// 		meta.enable_equality(d);
// 		meta.enable_equality(e);

// 		meta.enable_equality(instance);

// 		meta.create_gate("main_gate", |meta| {
// 			let a = meta.query_advice(a, Rotation::cur());
// 			let b = meta.query_advice(b, Rotation::cur());
// 			let c = meta.query_advice(c, Rotation::cur());
// 			let d = meta.query_advice(d, Rotation::cur());
// 			let e = meta.query_advice(e, Rotation::cur());

// 			let sa = meta.query_fixed(sa, Rotation::cur());
// 			let sb = meta.query_fixed(sb, Rotation::cur());
// 			let sc = meta.query_fixed(sc, Rotation::cur());
// 			let sd = meta.query_fixed(sd, Rotation::cur());
// 			let se = meta.query_fixed(se, Rotation::cur());

// 			let s_mul_ab = meta.query_fixed(s_mul_ab, Rotation::cur());
// 			let s_mul_cd = meta.query_fixed(s_mul_cd, Rotation::cur());

// 			let s_constant = meta.query_fixed(s_constant, Rotation::cur());

// 			vec![
// 				a.clone() * sa
// 					+ b.clone() * sb + c.clone() * sc
// 					+ d.clone() * sd + e * se
// 					+ a * b * s_mul_ab + c * d * s_mul_cd
// 					+ s_constant,
// 			]
// 		});

// 		MainGateConfig {
// 			a,
// 			b,
// 			c,
// 			d,
// 			e,
// 			sa,
// 			sb,
// 			sc,
// 			sd,
// 			se,
// 			s_mul_ab,
// 			s_mul_cd,
// 			s_constant,
// 			instance,
// 		}
// 	}
// }

// /// Structure for the main chip.
// pub struct MainGate<F: FieldExt> {
// 	values: Vec<AssignedCell<F, F>>,
// 	coeffs: [F; NUM_FIXED],
// }

// impl<F: FieldExt> MainGate<F> {
// 	/// Assigns a new witness that is equal to boolean AND of `x` and `y`
// 	pub fn and(
// 		// Assigns a cell for the x.
// 		x: AssignedCell<F, F>,
// 		// Assigns a cell for the y.
// 		y: AssignedCell<F, F>,
// 		config: &MainGateConfig,
// 		layouter: impl Layouter<F> + Copy,
// 	) -> Result<AssignedCell<F, F>, Error> {
// 		// Both of the `x` & `y` have to be boolean.
// 		let x = MainGate::is_bool(x, config, layouter)?;
// 		let y = MainGate::is_bool(y, config, layouter)?;

// 		MainGate::mul(x, y, config, layouter)
// 	}

// 	/// Assigns a new witness that is either of `0` or `1`
// 	pub fn is_bool(
// 		// Assigns a cell for the x.
// 		x: AssignedCell<F, F>,
// 		config: &MainGateConfig,
// 		mut layouter: impl Layouter<F>,
// 	) -> Result<AssignedCell<F, F>, Error> {
// 		// We should satisfy the equation below
// 		// (1 - x) * x = 0
// 		// x - x * x = 0

// 		// Witness layout:
// 		// | A   | B   | C   | D   | E  |
// 		// | --- | --- | --- | --- | ---|
// 		// | x   |     | x   | x   |    |

// 		layouter.assign_region(
// 			|| "is_bool",
// 			|region| {
// 				let mut ctx = RegionCtx::new(region, 0);

// 				ctx.assign_fixed(config.sa, F::one())?;
// 				ctx.assign_fixed(config.s_mul_cd, -F::one())?;

// 				let assigned_x = ctx.assign_advice(config.a, x.value().cloned())?;
// 				ctx.copy_assign(config.c, assigned_x.clone())?;
// 				ctx.copy_assign(config.d, assigned_x.clone())?;

// 				Ok(assigned_x)
// 			},
// 		)
// 	}

// 	/// Assigns a new witness (`x`) that is equal to `y`
// 	pub fn is_equal(
// 		x: AssignedCell<F, F>, y: AssignedCell<F, F>, config: &MainGateConfig,
// 		mut layouter: impl Layouter<F>,
// 	) -> Result<AssignedCell<F, F>, Error> {
// 		// We should satisfy the equation below
// 		// x - y = 0

// 		// Witness layout:
// 		// | A   | B   | C   | D   | E  |
// 		// | --- | --- | --- | --- | ---|
// 		// | x   | y   |  0  |     |    |

// 		layouter.assign_region(
// 			|| "is_equal",
// 			|region| {
// 				let mut ctx = RegionCtx::new(region, 0);

// 				ctx.assign_fixed(config.sa, F::one())?;
// 				ctx.assign_fixed(config.sb, -F::one())?;

// 				let assigned_x = ctx.assign_advice(config.a, x.value().cloned())?;
// 				ctx.assign_advice(config.b, y.value().cloned())?;

// 				Ok(assigned_x)
// 			},
// 		)
// 	}

// 	/// Assigns a new witness that is `zero`
// 	pub fn is_zero(
// 		// Assigns a cell for the x.
// 		x: AssignedCell<F, F>,
// 		config: &MainGateConfig,
// 		mut layouter: impl Layouter<F>,
// 	) -> Result<AssignedCell<F, F>, Error> {
// 		// We should satisfy the equation below
// 		// 1 - x * x_inv = 1
// 		// x * x_inv = 0

// 		// Witness layout:
// 		// | A   | B     | C   | D   | E  |
// 		// | --- | ----- | --- | --- | ---|
// 		// | x   | x_inv |     |     |    |

// 		layouter.assign_region(
// 			|| "is_zero",
// 			|region| {
// 				let x_inv = x.clone().value().map(|v| v.invert().unwrap_or(F::zero()));

// 				let mut ctx = RegionCtx::new(region, 0);

// 				ctx.assign_fixed(config.s_mul_ab, F::one())?;

// 				let assigned_x = ctx.copy_assign(config.a, x.clone())?;
// 				ctx.assign_advice(config.b, x_inv)?;

// 				Ok(assigned_x)
// 			},
// 		)
// 	}

// 	/// Assigns a new witness that is the product of `x` and `y`
// 	pub fn mul(
// 		// Assigns a cell for the x.
// 		x: AssignedCell<F, F>,
// 		// Assigns a cell for the y.
// 		y: AssignedCell<F, F>,
// 		config: &MainGateConfig,
// 		mut layouter: impl Layouter<F>,
// 	) -> Result<AssignedCell<F, F>, Error> {
// 		// We should satisfy the equation below
// 		// x * y - res = 0

// 		// Witness layout:
// 		// | A   | B   | C   | D   | E  |
// 		// | --- | --- | --- | --- | ---|
// 		// | x   | y   | res |     |    |

// 		layouter.assign_region(
// 			|| "mul",
// 			|region| {
// 				let mut ctx = RegionCtx::new(region, 0);

// 				ctx.assign_fixed(config.s_mul_ab, F::one())?;
// 				ctx.assign_fixed(config.sc, -F::one())?;

// 				let assigned_x = ctx.assign_advice(config.a, x.value().cloned())?;
// 				let assigned_y = ctx.assign_advice(config.b, y.value().cloned())?;

// 				let prod = assigned_x.value().cloned() * assigned_y.value();
// 				let assigned_prod = ctx.assign_advice(config.c, prod)?;

// 				Ok(assigned_prod)
// 			},
// 		)
// 	}

// 	/// Assigns a new witness that is sum of `x` and `y`
// 	pub fn add(
// 		// Assigns a cell for the x.
// 		x: AssignedCell<F, F>,
// 		// Assigns a cell for the y.
// 		y: AssignedCell<F, F>,
// 		config: &MainGateConfig,
// 		mut layouter: impl Layouter<F>,
// 	) -> Result<AssignedCell<F, F>, Error> {
// 		// We should satisfy the equation below
// 		// x + y - res = 0

// 		// Witness layout:
// 		// | A   | B   | C   | D   | E  |
// 		// | --- | --- | --- | --- | ---|
// 		// | x   | y   | res |     |    |

// 		layouter.assign_region(
// 			|| "add",
// 			|region| {
// 				let mut ctx = RegionCtx::new(region, 0);

// 				ctx.assign_fixed(config.sa, F::one())?;
// 				ctx.assign_fixed(config.sb, F::one())?;
// 				ctx.assign_fixed(config.sc, -F::one())?;

// 				let assigned_x = ctx.assign_advice(config.a, x.value().cloned())?;
// 				let assigned_y = ctx.assign_advice(config.b, y.value().cloned())?;

// 				let sum = assigned_x.value().cloned() + assigned_y.value();
// 				let assigned_sum = ctx.assign_advice(config.c, sum)?;

// 				Ok(assigned_sum)
// 			},
// 		)
// 	}

// 	/// Assigns new witness that equals to `x` if `bit` is true or assigned to
// 	/// `y` if `bit` is false
// 	pub fn select(
// 		// Assigns a cell for the bit.
// 		bit: AssignedCell<F, F>,
// 		// Assigns a cell for the x.
// 		x: AssignedCell<F, F>,
// 		// Assigns a cell for the y.
// 		y: AssignedCell<F, F>,
// 		config: &MainGateConfig,
// 		mut layouter: impl Layouter<F>,
// 	) -> Result<AssignedCell<F, F>, Error> {
// 		// We should satisfy the equation below with bit asserted condition flag
// 		// c (x-y) + y - res = 0
// 		// cond * x - cond * y + y - res = 0

// 		// Witness layout:
// 		// | A   | B   | C | D   | E  |
// 		// | --- | --- | - | --- | ---|
// 		// | c   | x   | c | y   | res|

// 		let res = x.value().zip(y.value()).zip(bit.value()).map(|((x, y), bit)| {
// 			if *bit == F::one() {
// 				*x
// 			} else {
// 				assert_eq!(*bit, F::zero());
// 				*y
// 			}
// 		});

// 		layouter.assign_region(
// 			|| "select",
// 			|region| {
// 				let mut ctx = RegionCtx::new(region, 0);

// 				ctx.assign_fixed(config.s_mul_ab, F::one())?;
// 				ctx.assign_fixed(config.s_mul_cd, -F::one())?;
// 				ctx.assign_fixed(config.sd, F::one())?;
// 				ctx.assign_fixed(config.se, -F::one())?;

// 				let b1 = ctx.assign_advice(config.a, bit.value().cloned())?;
// 				ctx.assign_advice(config.b, x.value().cloned())?;
// 				let b2 = ctx.assign_advice(config.c, bit.value().cloned())?;
// 				ctx.assign_advice(config.d, y.value().cloned())?;
// 				let res = ctx.assign_advice(config.e, res)?;

// 				ctx.constrain_equal(b1, b2)?;

// 				Ok(res)
// 			},
// 		)
// 	}
// }

// impl<F: FieldExt> Chip<F> for MainGate<F> {
// 	type Output = AssignedCell<F, F>;

// 	fn configure(
// 		common: &crate::CommonConfig, meta: &mut ConstraintSystem<F>,
// 	) -> halo2::plonk::Selector {
// 		let selector = meta.selector();

// 		// Gate for the `main` circuit.
// 		meta.create_gate("main", |v_cells| {
// 			let a = v_cells.query_advice(common.advice[0], Rotation::cur());
// 			let b = v_cells.query_advice(common.advice[1], Rotation::cur());
// 			let c = v_cells.query_advice(common.advice[2], Rotation::cur());
// 			let d = v_cells.query_advice(common.advice[3], Rotation::cur());
// 			let e = v_cells.query_advice(common.advice[4], Rotation::cur());

// 			let sa = v_cells.query_fixed(common.fixed[0], Rotation::cur());
// 			let sb = v_cells.query_fixed(common.fixed[1], Rotation::cur());
// 			let sc = v_cells.query_fixed(common.fixed[2], Rotation::cur());
// 			let sd = v_cells.query_fixed(common.fixed[3], Rotation::cur());
// 			let se = v_cells.query_fixed(common.fixed[4], Rotation::cur());

// 			let s_mul_ab = v_cells.query_fixed(common.fixed[5], Rotation::cur());
// 			let s_mul_cd = v_cells.query_fixed(common.fixed[6], Rotation::cur());

// 			let s_constant = v_cells.query_fixed(common.fixed[7], Rotation::cur());

// 			let _instance = v_cells.query_instance(common.instance, Rotation::cur());

// 			let selector = v_cells.query_selector(selector);

// 			vec![
// 				selector
// 					* (a.clone() * sa
// 						+ b.clone() * sb + c.clone() * sc
// 						+ d.clone() * sd + e * se
// 						+ a * b * s_mul_ab + c * d * s_mul_cd
// 						+ s_constant),
// 			]
// 		});

// 		selector
// 	}

// 	fn synthesize(
// 		self, common: &crate::CommonConfig, selector: &halo2::plonk::Selector,
// 		mut layouter: impl Layouter<F>,
// 	) -> Result<Self::Output, Error> {
// 		layouter.assign_region(
// 			|| "main chip",
// 			|region| {
// 				let mut ctx = RegionCtx::new(region, 0);

// 				self.values
// 					.clone()
// 					.into_iter()
// 					.enumerate()
// 					.map(|(i, v)| ctx.assign_advice(common.advice[i], v.value().cloned()))
// 					.collect::<Result<Vec<_>, Error>>()?;

// 				self.coeffs
// 					.clone()
// 					.into_iter()
// 					.enumerate()
// 					.map(|(i, v)| ctx.assign_fixed(common.fixed[i], v))
// 					.collect::<Result<Vec<_>, Error>>()?;

// 				ctx.enable(*selector)?;

// 				todo!()
// 			},
// 		)
// 	}
// }

#[derive(Copy, Clone, Debug)]
/// Configuration elements for the circuit are defined here.
pub struct MainConfig {
	/// Configures columns for the advice.
	advice: [Column<Advice>; NUM_ADVICE],

	/// Configures the fixed boolean values for each row of the circuit.
	fixed: [Column<Fixed>; NUM_FIXED],

	instance: Column<Instance>,

	selector: Selector,
}

impl MainConfig {
	/// Create a new `MainConfig` columns
	pub fn new<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
		let advice = [(); NUM_ADVICE].map(|_| meta.advice_column());
		let fixed = [(); NUM_FIXED].map(|_| meta.fixed_column());
		let instance = meta.instance_column();

		advice.map(|c| meta.enable_equality(c));
		fixed.map(|c| meta.enable_constant(c));
		meta.enable_equality(instance);

		let selector = meta.selector();

		Self { advice, fixed, instance, selector }
	}
}

/// Structure for the main chip.
pub struct MainChip<F: FieldExt> {
	advice: [AssignedCell<F, F>; NUM_ADVICE],
	fixed: [F; NUM_FIXED],
}

impl<F: FieldExt> MainChip<F> {
	/// Assigns a new witness that is equal to boolean AND of `x` and `y`
	pub fn new(advice: [AssignedCell<F, F>; NUM_ADVICE], fixed: [F; NUM_FIXED]) -> Self {
		Self { advice, fixed }
	}
}

impl<F: FieldExt> Chip<F> for MainChip<F> {
	type Output = ();

	fn configure(
		common: &crate::CommonConfig, meta: &mut ConstraintSystem<F>,
	) -> halo2::plonk::Selector {
		let selector = meta.selector();

		meta.create_gate("main gate", |v_cells| {
			// MainGate constraints
			let a = v_cells.query_advice(common.advice[0], Rotation::cur());
			let b = v_cells.query_advice(common.advice[1], Rotation::cur());
			let c = v_cells.query_advice(common.advice[2], Rotation::cur());
			let d = v_cells.query_advice(common.advice[3], Rotation::cur());
			let e = v_cells.query_advice(common.advice[4], Rotation::cur());

			let sa = v_cells.query_fixed(common.fixed[0], Rotation::cur());
			let sb = v_cells.query_fixed(common.fixed[1], Rotation::cur());
			let sc = v_cells.query_fixed(common.fixed[2], Rotation::cur());
			let sd = v_cells.query_fixed(common.fixed[3], Rotation::cur());
			let se = v_cells.query_fixed(common.fixed[4], Rotation::cur());

			let s_mul_ab = v_cells.query_fixed(common.fixed[5], Rotation::cur());
			let s_mul_cd = v_cells.query_fixed(common.fixed[6], Rotation::cur());

			let s_constant = v_cells.query_fixed(common.fixed[7], Rotation::cur());

			let _instance = v_cells.query_instance(common.instance, Rotation::cur());

			let selector = v_cells.query_selector(selector);

			vec![
				selector
					* (a.clone() * sa
						+ b.clone() * sb + c.clone() * sc
						+ d.clone() * sd + e * se
						+ a * b * s_mul_ab + c * d * s_mul_cd
						+ s_constant),
			]
		});
		selector
	}

	fn synthesize(
		self, common: &crate::CommonConfig, selector: &halo2::plonk::Selector,
		mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		layouter.assign_region(
			|| "main gate",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);

				ctx.enable(*selector)?;

				self.advice
					.clone()
					.into_iter()
					.enumerate()
					.map(|(i, v)| ctx.assign_advice(common.advice[i], v.value().cloned()))
					.collect::<Result<Vec<_>, Error>>()?;

				self.fixed
					.clone()
					.into_iter()
					.enumerate()
					.map(|(i, v)| ctx.assign_fixed(common.fixed[i], v))
					.collect::<Result<Vec<_>, Error>>()?;

				Ok(())
			},
		)
	}
}

/// Chip for addition operation
pub struct AddChipset<F: FieldExt> {
	x: AssignedCell<F, F>,
	y: AssignedCell<F, F>,
}

impl<F: FieldExt> AddChipset<F> {
	/// Create new AddChipset
	pub fn new(x: AssignedCell<F, F>, y: AssignedCell<F, F>) -> Self {
		Self { x, y }
	}
}

impl<F: FieldExt> Chipset<F> for AddChipset<F> {
	type Config = MainConfig;
	type Output = AssignedCell<F, F>;

	fn synthesize(
		self, common: &crate::CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		// We should satisfy the equation below
		// x + y - res = 0

		// Witness layout:
		// | A   | B   | C   | D   | E  |
		// | --- | --- | --- | --- | ---|
		// | x   | y   | res |     |    |

		let (zero, sum) = layouter.assign_region(
			|| "assign_values",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				let zero = ctx.assign_advice(common.advice[0], Value::known(F::zero()))?;
				let sum =
					ctx.assign_advice(common.advice[1], self.x.value().cloned() + self.y.value())?;
				Ok((zero, sum))
			},
		)?;

		let advices = [self.x, self.y, sum.clone(), zero.clone(), zero];
		let fixed =
			[F::one(), F::one(), -F::one(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(common, &config.selector, layouter)?;

		Ok(sum)
	}
}

/// Chip for multiplication operation
pub struct MulChipset<F: FieldExt> {
	x: AssignedCell<F, F>,
	y: AssignedCell<F, F>,
}

impl<F: FieldExt> MulChipset<F> {
	/// Create new MulChipset
	pub fn new(x: AssignedCell<F, F>, y: AssignedCell<F, F>) -> Self {
		Self { x, y }
	}
}

impl<F: FieldExt> Chipset<F> for MulChipset<F> {
	type Config = MainConfig;
	type Output = AssignedCell<F, F>;

	fn synthesize(
		self, common: &crate::CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		// We should satisfy the equation below
		// x * y - res = 0

		// Witness layout:
		// | A   | B   | C   | D   | E  |
		// | --- | --- | --- | --- | ---|
		// | x   | y   | res |     |    |

		let (zero, product) = layouter.assign_region(
			|| "assign_values",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				let zero = ctx.assign_advice(common.advice[0], Value::known(F::zero()))?;
				let product =
					ctx.assign_advice(common.advice[1], self.x.value().cloned() * self.y.value())?;
				Ok((zero, product))
			},
		)?;

		let advices = [self.x, self.y, product.clone(), zero.clone(), zero];
		let fixed =
			[F::zero(), F::zero(), -F::one(), F::zero(), F::zero(), F::one(), F::zero(), F::zero()];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(common, &config.selector, layouter)?;

		Ok(product)
	}
}

/// Chip for is_bool operation
pub struct IsBoolChipset<F: FieldExt> {
	x: AssignedCell<F, F>,
}

impl<F: FieldExt> IsBoolChipset<F> {
	/// Create new IsBoolChipset
	pub fn new(x: AssignedCell<F, F>) -> Self {
		Self { x }
	}
}

impl<F: FieldExt> Chipset<F> for IsBoolChipset<F> {
	type Config = MainConfig;
	type Output = AssignedCell<F, F>;

	fn synthesize(
		self, common: &crate::CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		// We should satisfy the equation below
		// (1 - x) * x = 0
		// x - x * x = 0

		// Witness layout:
		// | A   | B   | C   | D   | E  |
		// | --- | --- | --- | --- | ---|
		// | x   |     | x   | x   |    |

		let zero = layouter.assign_region(
			|| "assign_values",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				let zero = ctx.assign_advice(common.advice[0], Value::known(F::zero()))?;
				Ok(zero)
			},
		)?;

		// [a, b, c, d, e]
		let advices = [self.x.clone(), zero.clone(), self.x.clone(), self.x.clone(), zero];
		// [s_a, s_b, s_c, s_d, s_e, s_mul_ab, s_mul_cd, s_constant]
		let fixed =
			[F::one(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), -F::one(), F::zero()];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(common, &config.selector, layouter)?;

		Ok(self.x.clone())
	}
}

/// Chip for is_equal operation
pub struct IsEqualChipset<F: FieldExt> {
	x: AssignedCell<F, F>,
	y: AssignedCell<F, F>,
}

impl<F: FieldExt> IsEqualChipset<F> {
	/// Create new IsEqualChipset
	pub fn new(x: AssignedCell<F, F>, y: AssignedCell<F, F>) -> Self {
		Self { x, y }
	}
}

impl<F: FieldExt> Chipset<F> for IsEqualChipset<F> {
	type Config = MainConfig;
	type Output = AssignedCell<F, F>;

	fn synthesize(
		self, common: &crate::CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		// We should satisfy the equation below
		// x - y = 0

		// Witness layout:
		// | A   | B   | C   | D   | E  |
		// | --- | --- | --- | --- | ---|
		// | x   | y   |  0  |     |    |

		let zero = layouter.assign_region(
			|| "assign_values",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				let zero = ctx.assign_advice(common.advice[0], Value::known(F::zero()))?;
				Ok(zero)
			},
		)?;

		// [a, b, c, d, e]
		let advices = [self.x.clone(), self.y, zero.clone(), zero.clone(), zero];
		// [s_a, s_b, s_c, s_d, s_e, s_mul_ab, s_mul_cd, s_constant]
		let fixed =
			[F::one(), -F::one(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(common, &config.selector, layouter)?;

		Ok(self.x.clone())
	}
}

/// Chip for is_zero operation
pub struct IsZeroChipset<F: FieldExt> {
	x: AssignedCell<F, F>,
}

impl<F: FieldExt> IsZeroChipset<F> {
	/// Create new IsZeroChipset
	pub fn new(x: AssignedCell<F, F>) -> Self {
		Self { x }
	}
}

impl<F: FieldExt> Chipset<F> for IsZeroChipset<F> {
	type Config = MainConfig;
	type Output = AssignedCell<F, F>;

	fn synthesize(
		self, common: &crate::CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		// We should satisfy the equation below
		// 1 - x * x_inv = 1
		// x * x_inv = 0

		// Witness layout:
		// | A   | B     | C   | D   | E  |
		// | --- | ----- | --- | --- | ---|
		// | x   | x_inv |     |     |    |

		let (zero, x_inv) = layouter.assign_region(
			|| "assign_values",
			|region| {
				let x_inv = self.x.clone().value().map(|v| v.invert().unwrap_or(F::zero()));

				let mut ctx = RegionCtx::new(region, 0);
				let zero = ctx.assign_advice(common.advice[0], Value::known(F::zero()))?;
				let x_inv = ctx.assign_advice(common.advice[1], x_inv)?;
				Ok((zero, x_inv))
			},
		)?;

		// [a, b, c, d, e]
		let advices = [self.x.clone(), x_inv, zero.clone(), zero.clone(), zero];
		// [s_a, s_b, s_c, s_d, s_e, s_mul_ab, s_mul_cd, s_constant]
		let fixed =
			[F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::one(), F::zero(), F::zero()];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(common, &config.selector, layouter)?;

		Ok(self.x.clone())
	}
}

/// Chip for select operation
pub struct SelectChipset<F: FieldExt> {
	bit: AssignedCell<F, F>,
	x: AssignedCell<F, F>,
	y: AssignedCell<F, F>,
}

impl<F: FieldExt> SelectChipset<F> {
	/// Create new SelectChipset
	pub fn new(bit: AssignedCell<F, F>, x: AssignedCell<F, F>, y: AssignedCell<F, F>) -> Self {
		Self { bit, x, y }
	}
}

impl<F: FieldExt> Chipset<F> for SelectChipset<F> {
	type Config = MainConfig;
	type Output = AssignedCell<F, F>;

	fn synthesize(
		self, common: &crate::CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		// We should satisfy the equation below with bit asserted condition flag
		// c (x - y) + y - res = 0
		// cond * x - cond * y + y - res = 0

		// Witness layout:
		// | A   | B   | C | D   | E  |
		// | --- | --- | - | --- | ---|
		// | c   | x   | c | y   | res|

		let res = layouter.assign_region(
			|| "assign values",
			|region| {
				let res = self.x.value().zip(self.y.value()).zip(self.bit.value()).map(
					|((x, y), bit)| {
						if *bit == F::one() {
							*x
						} else {
							assert_eq!(*bit, F::zero());
							*y
						}
					},
				);
				let mut ctx = RegionCtx::new(region, 0);
				let res = ctx.assign_advice(common.advice[0], res)?;
				Ok(res)
			},
		)?;

		// [a, b, c, d, e]
		let advices = [self.bit.clone(), self.x, self.bit.clone(), self.y, res.clone()];
		// [s_a, s_b, s_c, s_d, s_e, s_mul_ab, s_mul_cd, s_constant]
		let fixed =
			[F::zero(), F::zero(), F::zero(), F::one(), -F::one(), F::one(), -F::one(), F::zero()];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(common, &config.selector, layouter)?;

		Ok(res)
	}
}

/// Chip for AND operation
pub struct AndChipset<F: FieldExt> {
	x: AssignedCell<F, F>,
	y: AssignedCell<F, F>,
}

impl<F: FieldExt> AndChipset<F> {
	/// Create new AndChipset
	pub fn new(x: AssignedCell<F, F>, y: AssignedCell<F, F>) -> Self {
		Self { x, y }
	}
}

impl<F: FieldExt> Chipset<F> for AndChipset<F> {
	type Config = MainConfig;
	type Output = AssignedCell<F, F>;

	fn synthesize(
		self, common: &crate::CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		let bool_chip = IsBoolChipset::new(self.x.clone());
		bool_chip.synthesize(common, &config, layouter.namespace(|| "constraint bit"))?;

		let bool_chip = IsBoolChipset::new(self.y.clone());
		bool_chip.synthesize(common, &config, layouter.namespace(|| "constraint bit"))?;

		let mul_chip = MulChipset::new(self.x, self.y);
		let product = mul_chip.synthesize(common, &config, layouter.namespace(|| "mul"))?;

		Ok(product)
	}
}
