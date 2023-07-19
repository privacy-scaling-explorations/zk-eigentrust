//! `main_gate` is a five width standard like PLONK gate that constrains the
//! equation below
//!
//! q_a * a + q_b * b + q_c * c + q_d * d + q_e * e +
//! q_mul_ab * a * b +
//! q_mul_cd * c * d +
//! public_input +
//! q_constant = 0

use crate::{Chip, Chipset, CommonConfig, FieldExt, RegionCtx};
use halo2::{
	circuit::{AssignedCell, Layouter, Value},
	plonk::{ConstraintSystem, Error, Selector},
	poly::Rotation,
};

/// Number of advice columns in MainChip
pub const NUM_ADVICE: usize = 5;
/// Number of fixed columns in MainChip
pub const NUM_FIXED: usize = 8;

/// Main config for common primitives like `add`, `mul` ...
#[derive(Debug, Clone)]
pub struct MainConfig {
	selector: Selector,
}

impl MainConfig {
	/// Initialization function for MainConfig
	pub fn new(selector: Selector) -> Self {
		Self { selector }
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

	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector {
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
		self, common: &CommonConfig, selector: &Selector, mut layouter: impl Layouter<F>,
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
					.map(|(i, v)| ctx.copy_assign(common.advice[i], v))
					.collect::<Result<Vec<_>, Error>>()?;

				self.fixed
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
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
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
				let zero = ctx.assign_advice(common.advice[0], Value::known(F::ZERO))?;
				let sum =
					ctx.assign_advice(common.advice[1], self.x.value().cloned() + self.y.value())?;
				Ok((zero, sum))
			},
		)?;

		let advices = [self.x, self.y, sum.clone(), zero.clone(), zero];
		let fixed = [F::ONE, F::ONE, -F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(common, &config.selector, layouter.namespace(|| "main_add"))?;

		Ok(sum)
	}
}

/// Chip for subtract operation
pub struct SubChipset<F: FieldExt> {
	x: AssignedCell<F, F>,
	y: AssignedCell<F, F>,
}

impl<F: FieldExt> SubChipset<F> {
	/// Create new SubChipset
	pub fn new(x: AssignedCell<F, F>, y: AssignedCell<F, F>) -> Self {
		Self { x, y }
	}
}

impl<F: FieldExt> Chipset<F> for SubChipset<F> {
	type Config = MainConfig;
	type Output = AssignedCell<F, F>;

	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		// We should satisfy the equation below
		// x - y - res = 0

		// Witness layout:
		// | A   | B   | C   | D   | E  |
		// | --- | --- | --- | --- | ---|
		// | x   | y   | res |     |    |

		let (zero, diff) = layouter.assign_region(
			|| "assign_values",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				let zero = ctx.assign_advice(common.advice[0], Value::known(F::ZERO))?;
				let diff =
					ctx.assign_advice(common.advice[1], self.x.value().cloned() - self.y.value())?;
				Ok((zero, diff))
			},
		)?;

		let advices = [self.x, self.y, diff.clone(), zero.clone(), zero];
		let fixed = [F::ONE, -F::ONE, -F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(common, &config.selector, layouter.namespace(|| "main_sub"))?;

		Ok(diff)
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
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
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
				let zero = ctx.assign_advice(common.advice[0], Value::known(F::ZERO))?;
				let product =
					ctx.assign_advice(common.advice[1], self.x.value().cloned() * self.y.value())?;
				Ok((zero, product))
			},
		)?;

		let advices = [self.x, self.y, product.clone(), zero.clone(), zero];
		let fixed = [F::ZERO, F::ZERO, -F::ONE, F::ZERO, F::ZERO, F::ONE, F::ZERO, F::ZERO];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(common, &config.selector, layouter.namespace(|| "main_mul"))?;

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
	type Output = ();

	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
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
				let zero = ctx.assign_advice(common.advice[0], Value::known(F::ZERO))?;
				Ok(zero)
			},
		)?;

		// [a, b, c, d, e]
		let advices = [self.x.clone(), zero.clone(), self.x.clone(), self.x, zero];
		// [s_a, s_b, s_c, s_d, s_e, s_mul_ab, s_mul_cd, s_constant]
		let fixed = [F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO, -F::ONE, F::ZERO];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(
			common,
			&config.selector,
			layouter.namespace(|| "main_is_bool"),
		)?;

		Ok(())
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
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		// We should satisfy the equation below
		// x - y = 0

		let sub_chip = SubChipset::new(self.x, self.y);
		let diff = sub_chip.synthesize(common, config, layouter.namespace(|| "sub"))?;

		let is_zero_chip = IsZeroChipset::new(diff);
		let res = is_zero_chip.synthesize(common, config, layouter.namespace(|| "is_zero"))?;

		Ok(res)
	}
}

/// Chip for calculating and constraining an inverse value
///
/// Chip returns if `x` is
/// 	- invertible : `1/x`
/// 	- non-invertible: `1`
pub struct InverseChipset<F: FieldExt> {
	x: AssignedCell<F, F>,
}

impl<F: FieldExt> InverseChipset<F> {
	/// Create new InverseChipset
	pub fn new(x: AssignedCell<F, F>) -> Self {
		Self { x }
	}
}

impl<F: FieldExt> Chipset<F> for InverseChipset<F> {
	type Config = MainConfig;
	type Output = AssignedCell<F, F>;

	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		// We should satisfy the equation below
		// 1 - x * x_inv = 0 (unsafe)

		// For the complete "inverse" operation,
		//
		// Returns 'r' as a condition bit that defines if inversion successful or not
		// First enforce 'r' to be a bit
		// (x * x_inv) - 1 + r = 0
		// r * x_inv - r = 0
		// if r = 1 then x_inv = 1
		// if r = 0 then x_inv = 1/x
		//
		// Witness layout:
		// | A | B     | C |
		// | - | ----- | - |
		// | x | x_inv | r |
		// | r | x_inv | r |
		//
		// Ref: https://github.com/privacy-scaling-explorations/halo2wrong/blob/master/maingate/src/instructions.rs#L417-L485

		let (zero, x_inv, r) = layouter.assign_region(
			|| "assign_values",
			|region| {
				let (r, x_inv) = self
					.x
					.clone()
					.value()
					.map(|v| {
						Option::from(v.invert())
							.map(|v_inv| (F::ZERO, v_inv))
							.unwrap_or_else(|| (F::ONE, F::ONE))
					})
					.unzip();

				let mut ctx = RegionCtx::new(region, 0);
				let zero = ctx.assign_advice(common.advice[0], Value::known(F::ZERO))?;
				let x_inv = ctx.assign_advice(common.advice[1], x_inv)?;
				let r = ctx.assign_advice(common.advice[2], r)?;
				Ok((zero, x_inv, r))
			},
		)?;

		// Enforce `r` to be bit
		let is_r_bit = IsBoolChipset::new(r.clone());
		is_r_bit.synthesize(common, config, layouter.namespace(|| "r * r - r = 0"))?;

		// (x * x_inv) - 1 + r = 0
		// | A | B     | C |
		// | - | ----- | - |
		// | x | x_inv | r |
		let advices = [self.x.clone(), x_inv.clone(), r.clone(), zero.clone(), zero.clone()];
		let fixed = [F::ZERO, F::ZERO, F::ONE, F::ZERO, F::ZERO, F::ONE, F::ZERO, -F::ONE];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(
			common,
			&config.selector,
			layouter.namespace(|| "x * x_inv + r - 1 = 0"),
		)?;

		// r * x_inv - r = 0
		// | A | B     | C |
		// | - | ----- | - |
		// | r | x_inv | r |
		let advices = [r.clone(), x_inv.clone(), r, zero.clone(), zero];
		let fixed = [F::ZERO, F::ZERO, -F::ONE, F::ZERO, F::ZERO, F::ONE, F::ZERO, F::ZERO];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(
			common,
			&config.selector,
			layouter.namespace(|| "r * x_inv - r = 0"),
		)?;

		Ok(x_inv)
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
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		// We should satisfy the equation below
		// res = 1 - x * x_inv = 0
		// x * x_inv = 1
		// x * x_inv + res - 1 = 0

		// Addional constraint:
		// x * res = x * (1 - x * x_inv) = 0

		// Witness layout:
		// | A   | B     | C   | D   | E  |
		// | --- | ----- | --- | --- | ---|
		// | x   | x_inv | res |     |    |
		// | x   | res   |

		let (zero, x_inv, res) = layouter.assign_region(
			|| "assign_values",
			|region| {
				let x_inv = self.x.clone().value().map(|v| v.invert().unwrap_or(F::ZERO));
				let res = Value::known(F::ONE) - self.x.clone().value().cloned() * x_inv;

				let mut ctx = RegionCtx::new(region, 0);
				let zero = ctx.assign_advice(common.advice[0], Value::known(F::ZERO))?;
				let x_inv = ctx.assign_advice(common.advice[1], x_inv)?;
				let res = ctx.assign_advice(common.advice[2], res)?;
				Ok((zero, x_inv, res))
			},
		)?;

		// [a, b, c, d, e]
		let advices = [self.x.clone(), x_inv, res.clone(), zero.clone(), zero.clone()];
		// [s_a, s_b, s_c, s_d, s_e, s_mul_ab, s_mul_cd, s_constant]
		let fixed = [F::ZERO, F::ZERO, F::ONE, F::ZERO, F::ZERO, F::ONE, F::ZERO, -F::ONE];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(common, &config.selector, layouter.namespace(|| "is_zero"))?;

		// Additional constraint
		// [a, b, c, d, e]
		let advices = [self.x, res.clone(), zero.clone(), zero.clone(), zero];
		// [s_a, s_b, s_c, s_d, s_e, s_mul_ab, s_mul_cd, s_constant]
		let fixed = [F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ONE, F::ZERO, F::ZERO];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(common, &config.selector, layouter.namespace(|| "mul"))?;

		Ok(res)
	}
}

/// Chip for select operation
#[derive(Debug, Clone)]
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
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
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
				let res = self
					.x
					.value()
					.zip(self.y.value())
					.zip(self.bit.value())
					.map(|((x, y), bit)| if *bit == F::ONE { *x } else { *y });
				let mut ctx = RegionCtx::new(region, 0);
				let res = ctx.assign_advice(common.advice[0], res)?;
				Ok(res)
			},
		)?;

		// Check if `bit` is really boolean
		let is_bool_chip = IsBoolChipset::new(self.bit.clone());
		is_bool_chip.synthesize(common, config, layouter.namespace(|| "is_bool"))?;

		// [a, b, c, d, e]
		let advices = [self.bit.clone(), self.x, self.bit.clone(), self.y, res.clone()];
		// [s_a, s_b, s_c, s_d, s_e, s_mul_ab, s_mul_cd, s_constant]
		let fixed = [F::ZERO, F::ZERO, F::ZERO, F::ONE, -F::ONE, F::ONE, -F::ONE, F::ZERO];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(
			common,
			&config.selector,
			layouter.namespace(|| "main_select"),
		)?;

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
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		let bool_chip = IsBoolChipset::new(self.x.clone());
		bool_chip.synthesize(common, config, layouter.namespace(|| "constraint bit"))?;

		let bool_chip = IsBoolChipset::new(self.y.clone());
		bool_chip.synthesize(common, config, layouter.namespace(|| "constraint bit"))?;

		let mul_chip = MulChipset::new(self.x, self.y);
		let product = mul_chip.synthesize(common, config, layouter.namespace(|| "mul"))?;

		Ok(product)
	}
}
/// Chip for OR operation
pub struct OrChipset<F: FieldExt> {
	x: AssignedCell<F, F>,
	y: AssignedCell<F, F>,
}

impl<F: FieldExt> OrChipset<F> {
	/// Create new OrChipset
	pub fn new(x: AssignedCell<F, F>, y: AssignedCell<F, F>) -> Self {
		Self { x, y }
	}
}

impl<F: FieldExt> Chipset<F> for OrChipset<F> {
	type Config = MainConfig;
	type Output = AssignedCell<F, F>;

	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		// We should satisfy the equation below
		// res = 1 - (1 - x) & (1 - y)
		//	   = 1 - (1 - x - y + xy)
		//	   = x + y - xy
		//
		// "&" can be replaced with "*" since bit checks
		//
		// Witness layout:
		// | A   | B   | C   | D   | E  |
		// | --- | --- | --- | --- | ---|
		// | x   | y   | res |     |    |
		let (res, zero) = layouter.assign_region(
			|| "assign values",
			|region| {
				let res = self.x.value().zip(self.y.value()).map(|(x, y)| *x + *y - *x * *y);
				let mut ctx = RegionCtx::new(region, 0);
				let res = ctx.assign_advice(common.advice[0], res)?;
				let zero = ctx.assign_advice(common.advice[1], Value::known(F::ZERO))?;
				Ok((res, zero))
			},
		)?;

		let bool_chip = IsBoolChipset::new(self.x.clone());
		bool_chip.synthesize(common, config, layouter.namespace(|| "constraint bit"))?;

		let bool_chip = IsBoolChipset::new(self.y.clone());
		bool_chip.synthesize(common, config, layouter.namespace(|| "constraint bit"))?;

		// [a, b, c, d, e]
		let advices = [self.x, self.y, res.clone(), zero.clone(), zero];
		// [s_a, s_b, s_c, s_d, s_e, s_mul_ab, s_mul_cd, s_constant]
		let fixed = [F::ONE, F::ONE, -F::ONE, F::ZERO, F::ZERO, -F::ONE, F::ZERO, F::ZERO];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(common, &config.selector, layouter.namespace(|| "main_or"))?;

		Ok(res)
	}
}

/// Chip for mul add operation
pub struct MulAddChipset<F: FieldExt> {
	x: AssignedCell<F, F>,
	y: AssignedCell<F, F>,
	z: AssignedCell<F, F>,
}

impl<F: FieldExt> MulAddChipset<F> {
	/// Create new MulAddChipset
	pub fn new(x: AssignedCell<F, F>, y: AssignedCell<F, F>, z: AssignedCell<F, F>) -> Self {
		Self { x, y, z }
	}
}

impl<F: FieldExt> Chipset<F> for MulAddChipset<F> {
	type Config = MainConfig;
	type Output = AssignedCell<F, F>;

	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		// We should satisfy the equation below
		// x * y + z - sum = 0

		// Witness layout:
		// |  A  |  B  |  C  |  D  |  E  |
		// | --- | --- | --- | --- | --- |
		// |  x  |  y  |  z  | sum |     |

		let (zero, sum) = layouter.assign_region(
			|| "assign_values",
			|region| {
				let mut ctx = RegionCtx::new(region, 0);
				let zero = ctx.assign_advice(common.advice[0], Value::known(F::ZERO))?;
				let sum = ctx.assign_advice(
					common.advice[1],
					self.x.value().cloned() * self.y.value() + self.z.value(),
				)?;
				Ok((zero, sum))
			},
		)?;

		let advices = [self.x, self.y, self.z, sum.clone(), zero];
		let fixed = [F::ZERO, F::ZERO, F::ONE, -F::ONE, F::ZERO, F::ONE, F::ZERO, F::ZERO];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(
			common,
			&config.selector,
			layouter.namespace(|| "main_mul_add"),
		)?;

		Ok(sum)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		utils::{generate_params, prove_and_verify},
		Chipset, CommonConfig,
	};
	use halo2::{
		circuit::{SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::bn256::{Bn256, Fr},
		plonk::Circuit,
	};

	use rand::thread_rng;

	#[derive(Clone)]
	struct TestConfig {
		common: CommonConfig,
		main: MainConfig,
	}

	impl TestConfig {
		fn new(meta: &mut ConstraintSystem<Fr>) -> Self {
			let common = CommonConfig::new(meta);
			let main = MainConfig::new(MainChip::configure(&common, meta));
			Self { common, main }
		}
	}

	#[derive(Clone)]
	struct AndTestCircuit {
		x: Value<Fr>,
		y: Value<Fr>,
	}

	impl AndTestCircuit {
		fn new(x: Fr, y: Fr) -> Self {
			Self { x: Value::known(x), y: Value::known(y) }
		}
	}

	impl Circuit<Fr> for AndTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { x: Value::unknown(), y: Value::unknown() }
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let (x, y) = layouter.assign_region(
				|| "temp",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					let x = ctx.assign_advice(config.common.advice[0], self.x)?;
					let y = ctx.assign_advice(config.common.advice[1], self.y)?;

					Ok((x, y))
				},
			)?;

			let and_chip = AndChipset::new(x, y);
			let and = and_chip.synthesize(
				&config.common,
				&config.main,
				layouter.namespace(|| "and chipset"),
			)?;
			layouter.constrain_instance(and.cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	// TEST CASES FOR THE AND CIRCUIT
	#[test]
	fn test_and_x1_y1() {
		// Testing x = 1 and y = 1.
		let test_chip = AndTestCircuit::new(Fr::from(1), Fr::from(1));

		let pub_ins = vec![Fr::from(1)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_and_x1_y0() {
		// Testing x = 1 and y = 0.
		let test_chip = AndTestCircuit::new(Fr::from(1), Fr::from(0));

		let pub_ins = vec![Fr::from(0)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_and_x0_y0() {
		// Testing x = 0 and y = 0.
		let test_chip = AndTestCircuit::new(Fr::from(0), Fr::from(0));

		let pub_ins = vec![Fr::from(0)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_and_x0_y1() {
		// Testing x = 0 and y = 1.
		let test_chip = AndTestCircuit::new(Fr::from(0), Fr::from(1));

		let pub_ins = vec![Fr::from(0)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_and_production() {
		let test_chip = AndTestCircuit::new(Fr::from(1), Fr::from(1));

		let k = 4;
		let rng = &mut thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::from(1)]], rng).unwrap();

		assert!(res);
	}

	#[derive(Clone)]
	struct OrTestCircuit {
		x: Value<Fr>,
		y: Value<Fr>,
	}

	impl OrTestCircuit {
		fn new(x: Fr, y: Fr) -> Self {
			Self { x: Value::known(x), y: Value::known(y) }
		}
	}

	impl Circuit<Fr> for OrTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { x: Value::unknown(), y: Value::unknown() }
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let (x, y) = layouter.assign_region(
				|| "temp",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					let x = ctx.assign_advice(config.common.advice[0], self.x)?;
					let y = ctx.assign_advice(config.common.advice[1], self.y)?;

					Ok((x, y))
				},
			)?;

			let or_chip = OrChipset::new(x, y);
			let or = or_chip.synthesize(
				&config.common,
				&config.main,
				layouter.namespace(|| "or chipset"),
			)?;
			layouter.constrain_instance(or.cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	#[test]
	fn test_or_x1_y1() {
		// Testing x = 1 and y = 1.
		let test_chip = OrTestCircuit::new(Fr::from(1), Fr::from(1));

		let pub_ins = vec![Fr::from(1)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	// TEST CASES FOR THE OR CIRCUIT
	#[test]
	fn test_or_x1_y0() {
		// Testing x = 1 and y = 0.
		let test_chip = OrTestCircuit::new(Fr::from(1), Fr::from(0));

		let pub_ins = vec![Fr::from(1)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_or_x0_y0() {
		// Testing x = 0 and y = 0.
		let test_chip = OrTestCircuit::new(Fr::from(0), Fr::from(0));

		let pub_ins = vec![Fr::from(0)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct IsBoolTestCircuit {
		x: Value<Fr>,
	}

	impl IsBoolTestCircuit {
		fn new(x: Fr) -> Self {
			Self { x: Value::known(x) }
		}
	}

	impl Circuit<Fr> for IsBoolTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { x: Value::unknown() }
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let x = layouter.assign_region(
				|| "temp",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					let x = ctx.assign_advice(config.common.advice[0], self.x)?;

					Ok(x)
				},
			)?;

			let bool_chip = IsBoolChipset::new(x);
			bool_chip.synthesize(
				&config.common,
				&config.main,
				layouter.namespace(|| "is bool chipset"),
			)?;

			Ok(())
		}
	}

	// TEST CASES FOR THE IS_BOOL CIRCUIT
	// In a IsBool test case sending a dummy instance doesn't
	// affect the circuit output because it is not constrained.
	#[test]
	fn test_is_bool_value_zero() {
		// Testing input zero as value.
		let test_chip = IsBoolTestCircuit::new(Fr::from(0));

		let k = 4;
		let dummy_instance = vec![];
		let prover = MockProver::run(k, &test_chip, vec![dummy_instance]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_bool_value_one() {
		// Testing input one as value.
		let test_chip = IsBoolTestCircuit::new(Fr::from(1));

		let k = 4;
		let dummy_instance = vec![];
		let prover = MockProver::run(k, &test_chip, vec![dummy_instance]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_bool_invalid_value() {
		// Testing input two as value, which is invalid for the boolean circuit.
		let test_chip = IsBoolTestCircuit::new(Fr::from(2));

		let k = 4;
		let dummy_instance = vec![];
		let prover = MockProver::run(k, &test_chip, vec![dummy_instance]).unwrap();
		assert!(prover.verify().is_err());
	}

	#[test]
	fn test_is_bool_production() {
		let test_chip = IsBoolTestCircuit::new(Fr::from(0));

		let k = 4;
		let rng = &mut thread_rng();
		let params = generate_params(k);
		let dummy_instance = vec![Fr::zero()];
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&dummy_instance], rng).unwrap();

		assert!(res);
	}

	#[derive(Clone)]
	struct IsEqualTestCircuit {
		x: Value<Fr>,
		y: Value<Fr>,
	}

	impl IsEqualTestCircuit {
		fn new(x: Fr, y: Fr) -> Self {
			Self { x: Value::known(x), y: Value::known(y) }
		}
	}

	impl Circuit<Fr> for IsEqualTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { x: Value::unknown(), y: Value::unknown() }
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let (x, y) = layouter.assign_region(
				|| "temp",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					let x = ctx.assign_advice(config.common.advice[0], self.x)?;
					let y = ctx.assign_advice(config.common.advice[1], self.y)?;

					Ok((x, y))
				},
			)?;

			let is_eq_chip = IsEqualChipset::new(x, y);
			let is_eq = is_eq_chip.synthesize(
				&config.common,
				&config.main,
				layouter.namespace(|| "is equal chipset"),
			)?;
			layouter.constrain_instance(is_eq.cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	// TEST CASES FOR THE IS_EQUAL CIRCUIT
	#[test]
	fn test_is_equal() {
		// Testing equal values.
		let test_chip = IsEqualTestCircuit::new(Fr::from(123), Fr::from(123));

		let pub_ins = vec![Fr::one()];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_not_equal() {
		// Testing not equal values.
		let test_chip = IsEqualTestCircuit::new(Fr::from(123), Fr::from(124));

		let pub_ins = vec![Fr::zero()];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_equal_production() {
		let test_chip = IsEqualTestCircuit::new(Fr::from(123), Fr::from(123));

		let k = 4;
		let rng = &mut thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::one()]], rng).unwrap();

		assert!(res);
	}

	#[derive(Clone)]
	struct IsZeroTestCircuit {
		x: Value<Fr>,
	}

	impl IsZeroTestCircuit {
		fn new(x: Fr) -> Self {
			Self { x: Value::known(x) }
		}
	}

	impl Circuit<Fr> for IsZeroTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { x: Value::unknown() }
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let x = layouter.assign_region(
				|| "temp",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					let x = ctx.assign_advice(config.common.advice[0], self.x)?;

					Ok(x)
				},
			)?;

			let is_zero_chip = IsZeroChipset::new(x);
			let is_zero = is_zero_chip.synthesize(
				&config.common,
				&config.main,
				layouter.namespace(|| "is zero chipset"),
			)?;
			layouter.constrain_instance(is_zero.cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	// TEST CASES FOR THE IS_ZERO CIRCUIT
	#[test]
	fn test_is_zero() {
		// Testing zero as value.
		let test_chip = IsZeroTestCircuit::new(Fr::from(0));

		let pub_ins = vec![Fr::one()];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_zero_not() {
		// Testing a non-zero value.
		let test_chip = IsZeroTestCircuit::new(Fr::from(1));

		let pub_ins = vec![Fr::zero()];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_zero_production() {
		let test_chip = IsZeroTestCircuit::new(Fr::from(0));

		let k = 4;
		let rng = &mut thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::one()]], rng).unwrap();

		assert!(res);
	}

	#[derive(Clone)]
	struct AddTestCircuit {
		x: Value<Fr>,
		y: Value<Fr>,
	}

	impl AddTestCircuit {
		fn new(x: Fr, y: Fr) -> Self {
			Self { x: Value::known(x), y: Value::known(y) }
		}
	}

	impl Circuit<Fr> for AddTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { x: Value::unknown(), y: Value::unknown() }
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let (x, y) = layouter.assign_region(
				|| "temp",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					let x = ctx.assign_advice(config.common.advice[0], self.x)?;
					let y = ctx.assign_advice(config.common.advice[1], self.y)?;

					Ok((x, y))
				},
			)?;

			let add_chip = AddChipset::new(x, y);
			let add = add_chip.synthesize(
				&config.common,
				&config.main,
				layouter.namespace(|| "add chipset"),
			)?;
			layouter.constrain_instance(add.cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	// TEST CASES FOR THE ADD CIRCUIT
	#[test]
	fn test_add() {
		// Testing x = 5 and y = 2.
		let test_chip = AddTestCircuit::new(Fr::from(5), Fr::from(2));

		let k = 4;
		let pub_ins = vec![Fr::from(5 + 2)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_add_y1() {
		// Testing x = 3 and y = 1.
		let test_chip = AddTestCircuit::new(Fr::from(3), Fr::from(1));

		let k = 4;
		let pub_ins = vec![Fr::from(3 + 1)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_add_y0() {
		// Testing x = 4 and y = 0.
		let test_chip = AddTestCircuit::new(Fr::from(4), Fr::from(0));

		let k = 4;
		let pub_ins = vec![Fr::from(4 + 0)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_add_production() {
		let test_chip = AddTestCircuit::new(Fr::from(5), Fr::from(2));

		let k = 4;
		let rng = &mut thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::from(5 + 2)]], rng).unwrap();

		assert!(res);
	}

	#[derive(Clone)]
	struct MulTestCircuit {
		x: Value<Fr>,
		y: Value<Fr>,
	}

	impl MulTestCircuit {
		fn new(x: Fr, y: Fr) -> Self {
			Self { x: Value::known(x), y: Value::known(y) }
		}
	}

	impl Circuit<Fr> for MulTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { x: Value::unknown(), y: Value::unknown() }
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let (x, y) = layouter.assign_region(
				|| "temp",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					let x = ctx.assign_advice(config.common.advice[0], self.x)?;
					let y = ctx.assign_advice(config.common.advice[1], self.y)?;

					Ok((x, y))
				},
			)?;

			let mul_chip = MulChipset::new(x, y);
			let mul = mul_chip.synthesize(
				&config.common,
				&config.main,
				layouter.namespace(|| "mul chipset"),
			)?;
			layouter.constrain_instance(mul.cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	// TEST CASES FOR THE MUL CIRCUIT
	#[test]
	fn test_mul() {
		// Testing x = 5 and y = 2.
		let test_chip = MulTestCircuit::new(Fr::from(5), Fr::from(2));

		let k = 4;
		let pub_ins = vec![Fr::from(10)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_mul_y1() {
		// Testing x = 3 and y = 1.
		let test_chip = MulTestCircuit::new(Fr::from(3), Fr::from(1));

		let k = 4;
		let pub_ins = vec![Fr::from(3)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_mul_y0() {
		// Testing x = 4 and y = 0.
		let test_chip = MulTestCircuit::new(Fr::from(4), Fr::from(0));

		let k = 4;
		let pub_ins = vec![Fr::from(0)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_mul_production() {
		let test_chip = MulTestCircuit::new(Fr::from(5), Fr::from(2));

		let k = 4;
		let rng = &mut thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::from(10)]], rng).unwrap();

		assert!(res);
	}

	#[derive(Clone)]
	struct SelectTestCircuit {
		bit: Value<Fr>,
		x: Value<Fr>,
		y: Value<Fr>,
	}

	impl SelectTestCircuit {
		fn new(bit: Fr, x: Fr, y: Fr) -> Self {
			Self { bit: Value::known(bit), x: Value::known(x), y: Value::known(y) }
		}
	}

	impl Circuit<Fr> for SelectTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { bit: Value::unknown(), x: Value::unknown(), y: Value::unknown() }
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let (bit, x, y) = layouter.assign_region(
				|| "temp",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					let bit = ctx.assign_advice(config.common.advice[0], self.bit)?;
					let x = ctx.assign_advice(config.common.advice[1], self.x)?;
					let y = ctx.assign_advice(config.common.advice[2], self.y)?;

					Ok((bit, x, y))
				},
			)?;

			let select_chip = SelectChipset::new(bit, x, y);
			let select = select_chip.synthesize(
				&config.common,
				&config.main,
				layouter.namespace(|| "select chipset"),
			)?;
			layouter.constrain_instance(select.cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	// TEST CASES FOR THE SELECT CIRCUIT
	#[test]
	fn test_select() {
		// Testing bit = 0.
		let test_chip = SelectTestCircuit::new(Fr::from(0), Fr::from(2), Fr::from(3));

		let pub_ins = vec![Fr::from(3)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_select_one_as_bit() {
		// Testing bit = 1.
		let test_chip = SelectTestCircuit::new(Fr::from(1), Fr::from(7), Fr::from(4));

		let pub_ins = vec![Fr::from(7)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_select_two_as_bit() {
		// Testing bit = 2. Constraint not satisfied error will return
		// because the bit is not a boolean value.
		let test_chip = SelectTestCircuit::new(Fr::from(2), Fr::from(3), Fr::from(6));

		let pub_ins = vec![Fr::from(3)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert!(prover.verify().is_err());
	}

	#[test]
	fn test_select_production() {
		let test_chip = SelectTestCircuit::new(Fr::from(0), Fr::from(2), Fr::from(3));

		let k = 4;
		let rng = &mut thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::from(3)]], rng).unwrap();

		assert!(res);
	}

	#[derive(Clone)]
	struct MulAddTestCircuit {
		x: Value<Fr>,
		y: Value<Fr>,
		z: Value<Fr>,
	}

	impl MulAddTestCircuit {
		fn new(x: Fr, y: Fr, z: Fr) -> Self {
			Self { x: Value::known(x), y: Value::known(y), z: Value::known(z) }
		}
	}

	impl Circuit<Fr> for MulAddTestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { x: Value::unknown(), y: Value::unknown(), z: Value::unknown() }
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let (x, y, z) = layouter.assign_region(
				|| "temp",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					let x = ctx.assign_advice(config.common.advice[0], self.x)?;
					let y = ctx.assign_advice(config.common.advice[1], self.y)?;
					let z = ctx.assign_advice(config.common.advice[2], self.z)?;

					Ok((x, y, z))
				},
			)?;

			let mul_add_chip = MulAddChipset::new(x, y, z);
			let mul_add = mul_add_chip.synthesize(
				&config.common,
				&config.main,
				layouter.namespace(|| "mul add chipset"),
			)?;
			layouter.constrain_instance(mul_add.cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	// TEST CASES FOR THE MUL ADD CIRCUIT
	#[test]
	fn test_mul_add() {
		// Testing x = 5, y = 2 and z = 3.
		let test_chip = MulAddTestCircuit::new(Fr::from(5), Fr::from(2), Fr::from(3));

		let k = 4;
		let pub_ins = vec![Fr::from(5 * 2 + 3)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_mul_add_big() {
		// Testing x = 5123, y = 22441 and z = 55621323.
		let test_chip = MulAddTestCircuit::new(Fr::from(5123), Fr::from(22441), Fr::from(55621323));

		let k = 4;
		let pub_ins = vec![Fr::from(5123 * 22441 + 55621323)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}
}
