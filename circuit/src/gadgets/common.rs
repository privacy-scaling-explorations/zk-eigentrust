//! `main_gate` is a five width standard like PLONK gate that constrains the
//! equation below
//!
//! q_a * a + q_b * b + q_c * c + q_d * d + q_e * e +
//! q_mul_ab * a * b +
//! q_mul_cd * c * d +
//! public_input +
//! q_constant = 0

use crate::{Chip, Chipset, CommonConfig, RegionCtx, ADVICE, FIXED};
use halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
	poly::Rotation,
};

/// Structure for the main chip.
pub struct MainChip<F: FieldExt> {
	advice: [AssignedCell<F, F>; ADVICE],
	fixed: [F; FIXED],
}

impl<F: FieldExt> MainChip<F> {
	/// Assigns a new witness that is equal to boolean AND of `x` and `y`
	pub fn new(advice: [AssignedCell<F, F>; ADVICE], fixed: [F; FIXED]) -> Self {
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
				let zero = ctx.assign_advice(common.advice[0], Value::known(F::zero()))?;
				let diff =
					ctx.assign_advice(common.advice[1], self.x.value().cloned() - self.y.value())?;
				Ok((zero, diff))
			},
		)?;

		let advices = [self.x, self.y, diff.clone(), zero.clone(), zero];
		let fixed =
			[F::one(), -F::one(), -F::one(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(common, &config.selector, layouter)?;

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
		// 1 - x * x_inv = 1
		// x * x_inv = 0
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
				let x_inv = self.x.clone().value().map(|v| v.invert().unwrap_or(F::zero()));
				let res = Value::known(F::one()) - self.x.clone().value().cloned() * x_inv.clone();

				let mut ctx = RegionCtx::new(region, 0);
				let zero = ctx.assign_advice(common.advice[0], Value::known(F::zero()))?;
				let x_inv = ctx.assign_advice(common.advice[1], x_inv)?;
				let res = ctx.assign_advice(common.advice[2], res)?;
				Ok((zero, x_inv, res))
			},
		)?;

		// [a, b, c, d, e]
		let advices = [self.x.clone(), x_inv, res.clone(), zero.clone(), zero.clone()];
		// [s_a, s_b, s_c, s_d, s_e, s_mul_ab, s_mul_cd, s_constant]
		let fixed =
			[F::zero(), F::zero(), F::one(), F::zero(), F::zero(), F::one(), F::zero(), -F::one()];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(common, &config.selector, layouter.namespace(|| "is_zero"))?;

		// Additional constraint
		// [a, b, c, d, e]
		let advices = [self.x, res.clone(), zero.clone(), zero.clone(), zero];
		// [s_a, s_b, s_c, s_d, s_e, s_mul_ab, s_mul_cd, s_constant]
		let fixed =
			[F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::one(), F::zero(), F::zero()];
		let main_chip = MainChip::new(advices, fixed);
		main_chip.synthesize(common, &config.selector, layouter.namespace(|| "mul"))?;

		Ok(res)
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
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		// We should satisfy the equation below with bit asserted condition flag
		// c (x - y) + y - res = 0
		// cond * x - cond * y + y - res = 0

		// Witness layout:
		// | A   | B   | C | D   | E  |
		// | --- | --- | - | --- | ---|
		// | c   | x   | c | y   | res|

		// Check if `bit` is really boolean
		let is_bool_chip = IsBoolChipset::new(self.bit.clone());
		is_bool_chip.synthesize(common, config, layouter.namespace(|| "is_bool"))?;

		let res = layouter.assign_region(
			|| "assign values",
			|region| {
				let res = self.x.value().zip(self.y.value()).zip(self.bit.value()).map(
					|((x, y), bit)| {
						if *bit == F::one() {
							*x
						} else {
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
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		utils::{generate_params, prove_and_verify},
		Chipset, CommonChip, CommonConfig,
	};
	use halo2::{
		circuit::{SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::bn256::{Bn256, Fr},
		plonk::Circuit,
	};

	use rand::thread_rng;

	#[derive(Clone)]
	enum Gadgets {
		And,
		IsBool,
		IsEqual,
		IsZero,
		Mul,
		Select,
		Add,
	}

	#[derive(Clone)]
	struct TestConfig {
		common: CommonConfig,
		main: MainConfig,
	}

	#[derive(Clone)]
	struct TestCircuit<F: FieldExt, const N: usize> {
		inputs: [F; N],
		gadget: Gadgets,
	}

	impl<F: FieldExt, const N: usize> TestCircuit<F, N> {
		fn new(inputs: [F; N], gadget: Gadgets) -> Self {
			Self { inputs, gadget }
		}
	}

	impl<F: FieldExt, const N: usize> Circuit<F> for TestCircuit<F, N> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
			let common = CommonChip::configure(meta);
			let selector = MainChip::configure(&common, meta);
			let main = MainConfig::construct_from_selector::<F>(&common, selector);
			TestConfig { common, main }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<F>,
		) -> Result<(), Error> {
			let items = layouter.assign_region(
				|| "temp",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					let mut items = Vec::new();
					for i in 0..N {
						let val = Value::known(self.inputs[i]);
						let x = ctx.assign_advice(config.common.advice[0], val)?;
						ctx.next();
						items.push(x);
					}
					Ok(items)
				},
			)?;

			match self.gadget {
				Gadgets::And => {
					let and_chip = AndChipset::new(items[0].clone(), items[1].clone());
					let and = and_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "and"),
					)?;
					layouter.constrain_instance(and.cell(), config.common.instance, 0)?;
				},
				Gadgets::IsBool => {
					let is_bool_chip = IsBoolChipset::new(items[0].clone());
					is_bool_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "is_bool"),
					)?;
				},
				Gadgets::IsEqual => {
					let is_equal_chip = IsEqualChipset::new(items[0].clone(), items[1].clone());
					let is_equal = is_equal_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "is_equal"),
					)?;
					layouter.constrain_instance(is_equal.cell(), config.common.instance, 0)?;
				},
				Gadgets::IsZero => {
					let is_zero_chip = IsZeroChipset::new(items[0].clone());
					let is_zero = is_zero_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "is_zero"),
					)?;
					layouter.constrain_instance(is_zero.cell(), config.common.instance, 0)?;
				},
				Gadgets::Add => {
					let add_chip = AddChipset::new(items[0].clone(), items[1].clone());
					let add = add_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "add"),
					)?;
					layouter.constrain_instance(add.cell(), config.common.instance, 0)?;
				},
				Gadgets::Mul => {
					let mul_chip = MulChipset::new(items[0].clone(), items[1].clone());
					let mul = mul_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "mul"),
					)?;
					layouter.constrain_instance(mul.cell(), config.common.instance, 0)?;
				},
				Gadgets::Select => {
					let select_chip =
						SelectChipset::new(items[0].clone(), items[1].clone(), items[2].clone());
					let select = select_chip.synthesize(
						&config.common,
						&config.main,
						layouter.namespace(|| "select"),
					)?;
					layouter.constrain_instance(select.cell(), config.common.instance, 0)?;
				},
			}

			Ok(())
		}
	}

	// TEST CASES FOR THE AND CIRCUIT
	#[test]
	fn test_and_x1_y1() {
		// Testing x = 1 and y = 1.
		let test_chip = TestCircuit::new([Fr::from(1), Fr::from(1)], Gadgets::And);

		let pub_ins = vec![Fr::from(1)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_and_x1_y0() {
		// Testing x = 1 and y = 0.
		let test_chip = TestCircuit::new([Fr::from(1), Fr::from(0)], Gadgets::And);

		let pub_ins = vec![Fr::from(0)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_and_x0_y0() {
		// Testing x = 0 and y = 0.
		let test_chip = TestCircuit::new([Fr::from(0), Fr::from(0)], Gadgets::And);

		let pub_ins = vec![Fr::from(0)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_and_x0_y1() {
		// Testing x = 0 and y = 1.
		let test_chip = TestCircuit::new([Fr::from(0), Fr::from(1)], Gadgets::And);

		let pub_ins = vec![Fr::from(0)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_and_production() {
		let test_chip = TestCircuit::new([Fr::from(1), Fr::from(1)], Gadgets::And);

		let k = 4;
		let rng = &mut thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::from(1)]], rng).unwrap();

		assert!(res);
	}

	// TEST CASES FOR THE IS_BOOL CIRCUIT
	// In a IsBool test case sending a dummy instance doesn't
	// affect the circuit output because it is not constrained.
	#[test]
	fn test_is_bool_value_zero() {
		// Testing input zero as value.
		let test_chip = TestCircuit::new([Fr::from(0)], Gadgets::IsBool);

		let k = 4;
		let dummy_instance = vec![Fr::zero()];
		let prover = MockProver::run(k, &test_chip, vec![dummy_instance]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_bool_value_one() {
		// Testing input one as value.
		let test_chip = TestCircuit::new([Fr::from(1)], Gadgets::IsBool);

		let k = 4;
		let dummy_instance = vec![Fr::zero()];
		let prover = MockProver::run(k, &test_chip, vec![dummy_instance]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_bool_invalid_value() {
		// Testing input two as value, which is invalid for the boolean circuit.
		let test_chip = TestCircuit::new([Fr::from(2)], Gadgets::IsBool);

		let k = 4;
		let dummy_instance = vec![Fr::zero()];
		let prover = MockProver::run(k, &test_chip, vec![dummy_instance]).unwrap();
		assert!(prover.verify().is_err());
	}

	#[test]
	fn test_is_bool_production() {
		let test_chip = TestCircuit::new([Fr::from(0)], Gadgets::IsBool);

		let k = 4;
		let rng = &mut thread_rng();
		let params = generate_params(k);
		let dummy_instance = vec![Fr::zero()];
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&dummy_instance], rng).unwrap();

		assert!(res);
	}

	// TEST CASES FOR THE IS_EQUAL CIRCUIT
	#[test]
	fn test_is_equal() {
		// Testing equal values.
		let test_chip = TestCircuit::new([Fr::from(123), Fr::from(123)], Gadgets::IsEqual);

		let pub_ins = vec![Fr::one()];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_not_equal() {
		// Testing not equal values.
		let test_chip = TestCircuit::new([Fr::from(123), Fr::from(124)], Gadgets::IsEqual);

		let pub_ins = vec![Fr::zero()];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_equal_production() {
		let test_chip = TestCircuit::new([Fr::from(123), Fr::from(123)], Gadgets::IsEqual);

		let k = 4;
		let rng = &mut thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::one()]], rng).unwrap();

		assert!(res);
	}

	// TEST CASES FOR THE IS_ZERO CIRCUIT
	#[test]
	fn test_is_zero() {
		// Testing zero as value.
		let test_chip = TestCircuit::new([Fr::from(0)], Gadgets::IsZero);

		let pub_ins = vec![Fr::one()];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_zero_not() {
		// Testing a non-zero value.
		let test_chip = TestCircuit::new([Fr::from(1)], Gadgets::IsZero);

		let pub_ins = vec![Fr::zero()];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_zero_production() {
		let test_chip = TestCircuit::new([Fr::from(0)], Gadgets::IsZero);

		let k = 4;
		let rng = &mut thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::one()]], rng).unwrap();

		assert!(res);
	}

	// TEST CASES FOR THE ADD CIRCUIT
	#[test]
	fn test_add() {
		// Testing x = 5 and y = 2.
		let test_chip = TestCircuit::new([Fr::from(5), Fr::from(2)], Gadgets::Add);

		let k = 4;
		let pub_ins = vec![Fr::from(5 + 2)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_add_y1() {
		// Testing x = 3 and y = 1.
		let test_chip = TestCircuit::new([Fr::from(3), Fr::from(1)], Gadgets::Add);

		let k = 4;
		let pub_ins = vec![Fr::from(3 + 1)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_add_y0() {
		// Testing x = 4 and y = 0.
		let test_chip = TestCircuit::new([Fr::from(4), Fr::from(0)], Gadgets::Add);

		let k = 4;
		let pub_ins = vec![Fr::from(4 + 0)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_add_production() {
		let test_chip = TestCircuit::new([Fr::from(5), Fr::from(2)], Gadgets::Add);

		let k = 4;
		let rng = &mut thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::from(5 + 2)]], rng).unwrap();

		assert!(res);
	}

	// TEST CASES FOR THE MUL CIRCUIT
	#[test]
	fn test_mul() {
		// Testing x = 5 and y = 2.
		let test_chip = TestCircuit::new([Fr::from(5), Fr::from(2)], Gadgets::Mul);

		let k = 4;
		let pub_ins = vec![Fr::from(10)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_mul_y1() {
		// Testing x = 3 and y = 1.
		let test_chip = TestCircuit::new([Fr::from(3), Fr::from(1)], Gadgets::Mul);

		let k = 4;
		let pub_ins = vec![Fr::from(3)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_mul_y0() {
		// Testing x = 4 and y = 0.
		let test_chip = TestCircuit::new([Fr::from(4), Fr::from(0)], Gadgets::Mul);

		let k = 4;
		let pub_ins = vec![Fr::from(0)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_mul_production() {
		let test_chip = TestCircuit::new([Fr::from(5), Fr::from(2)], Gadgets::Mul);

		let k = 4;
		let rng = &mut thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::from(10)]], rng).unwrap();

		assert!(res);
	}

	// TEST CASES FOR THE SELECT CIRCUIT
	#[test]
	fn test_select() {
		// Testing bit = 0.
		let test_chip = TestCircuit::new([Fr::from(0), Fr::from(2), Fr::from(3)], Gadgets::Select);

		let pub_ins = vec![Fr::from(3)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_select_one_as_bit() {
		// Testing bit = 1.
		let test_chip = TestCircuit::new([Fr::from(1), Fr::from(7), Fr::from(4)], Gadgets::Select);

		let pub_ins = vec![Fr::from(7)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_select_two_as_bit() {
		// Testing bit = 2. Constraint not satisfied error will return
		// because the bit is not a boolean value.
		let test_chip = TestCircuit::new([Fr::from(2), Fr::from(3), Fr::from(6)], Gadgets::Select);

		let pub_ins = vec![Fr::from(3)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert!(prover.verify().is_err());
	}

	#[test]
	fn test_select_production() {
		let test_chip = TestCircuit::new([Fr::from(0), Fr::from(2), Fr::from(3)], Gadgets::Select);

		let k = 4;
		let rng = &mut thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::from(3)]], rng).unwrap();

		assert!(res);
	}
}
