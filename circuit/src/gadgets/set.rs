use crate::{gadgets::main::IsZeroChipset, Chip, Chipset, CommonConfig, RegionCtx};
use halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region},
	plonk::{ConstraintSystem, Error, Selector},
	poly::Rotation,
};

use super::main::MainConfig;

/// A chip for checking item membership in a set of field values
pub struct SetChip<F: FieldExt> {
	/// Constructs items variable for the circuit.
	items: Vec<AssignedCell<F, F>>,
	/// Assigns a cell for the target.
	target: AssignedCell<F, F>,
}

impl<F: FieldExt> SetChip<F> {
	/// Constructs a new chip
	pub fn new(items: Vec<AssignedCell<F, F>>, target: AssignedCell<F, F>) -> Self {
		SetChip { items, target }
	}
}

impl<F: FieldExt> Chip<F> for SetChip<F> {
	type Output = AssignedCell<F, F>;

	/// Make the circuit config.
	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector {
		let selector = meta.selector();

		meta.create_gate("set_membership", |v_cells| {
			let target_exp = v_cells.query_advice(common.advice[0], Rotation::cur());

			let item_exp = v_cells.query_advice(common.advice[1], Rotation::cur());
			let diff_exp = v_cells.query_advice(common.advice[2], Rotation::cur());

			let product_exp = v_cells.query_advice(common.advice[3], Rotation::cur());
			let next_product_exp = v_cells.query_advice(common.advice[3], Rotation::next());

			let s_exp = v_cells.query_selector(selector);

			vec![
				// If the difference is equal to 0, that will make the next product equal to 0.
				// Example:
				// product_exp = 1
				// diff_exp = 0
				// Check the constraint (1 * 0 == next_product_exp)
				// That makes next_product_exp = 0
				// => (1 * 0) - 0 == 0
				s_exp.clone() * (product_exp * diff_exp.clone() - next_product_exp),
				s_exp * (target_exp - (diff_exp + item_exp)),
			]
		});

		selector
	}

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, selector: &Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		layouter.assign_region(
			|| "set_membership",
			|region: Region<'_, F>| {
				let mut ctx = RegionCtx::new(region, 0);

				let mut assigned_product = ctx.assign_from_constant(common.advice[3], F::one())?;
				let mut assigned_target = ctx.copy_assign(common.advice[0], self.target.clone())?;
				for i in 0..self.items.len() {
					ctx.enable(selector.clone())?;

					let item_value = ctx.copy_assign(common.advice[1], self.items[i].clone())?;

					// Calculating difference between given target and item from the set.
					let diff = self.target.value().cloned() - item_value.value().cloned();
					// If the difference is equal to 0, that means the target is in the set and next
					// product will become 0.
					let next_product = assigned_product.value().cloned() * diff;
					ctx.assign_advice(common.advice[2], diff)?;

					ctx.next();
					assigned_product = ctx.assign_advice(common.advice[3], next_product)?;
					assigned_target = ctx.copy_assign(common.advice[0], assigned_target)?;
				}

				Ok(assigned_product)
			},
		)
	}
}

#[derive(Debug, Clone)]
/// Selectors for a FixedSetChipset
pub struct SetConfig {
	main: MainConfig,
	set_selector: Selector,
}

impl SetConfig {
	/// Constructs a new config given the selectors
	pub fn new(set_selector: Selector, main: MainConfig) -> Self {
		Self { set_selector, main }
	}
}

/// A chipset for checking a set membership
/// Also contains the result inverter
pub struct SetChipset<F: FieldExt> {
	/// Constructs items variable for the circuit.
	items: Vec<AssignedCell<F, F>>,
	/// Assigns a cell for the target.
	target: AssignedCell<F, F>,
}

impl<F: FieldExt> SetChipset<F> {
	/// Constructs a new chip
	pub fn new(items: Vec<AssignedCell<F, F>>, target: AssignedCell<F, F>) -> Self {
		Self { items, target }
	}
}

impl<F: FieldExt> Chipset<F> for SetChipset<F> {
	type Config = SetConfig;
	type Output = AssignedCell<F, F>;

	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		let set_chip = SetChip::new(self.items, self.target);
		let res = set_chip.synthesize(
			common,
			&config.set_selector,
			layouter.namespace(|| "set_membership"),
		)?;

		let is_zero_chip = IsZeroChipset::new(res);
		let is_zero =
			is_zero_chip.synthesize(common, &config.main, layouter.namespace(|| "is_member"))?;

		Ok(is_zero)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		gadgets::main::MainChip,
		utils::{generate_params, prove_and_verify},
		CommonConfig,
	};
	use halo2::{
		arithmetic::Field,
		circuit::{SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::bn256::{Bn256, Fr},
		plonk::Circuit,
	};

	#[derive(Clone)]
	struct TestConfig {
		common: CommonConfig,
		set: SetConfig,
	}

	#[derive(Clone)]
	struct TestCircuit<F: FieldExt> {
		items: Vec<Value<F>>,
		target: Value<F>,
	}

	impl<F: FieldExt> TestCircuit<F> {
		fn new(items: Vec<F>, target: F) -> Self {
			Self {
				items: items.into_iter().map(|x| Value::known(x)).collect(),
				target: Value::known(target),
			}
		}
	}

	impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self {
				items: self.items.clone().into_iter().map(|_| Value::unknown()).collect(),
				target: Value::unknown(),
			}
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
			let common = CommonConfig::new(meta);
			let main = MainConfig::new(MainChip::configure(&common, meta));

			let set_selector = SetChip::configure(&common, meta);
			let set = SetConfig::new(set_selector, main);

			TestConfig { common, set }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<F>,
		) -> Result<(), Error> {
			let (numba, items) = layouter.assign_region(
				|| "temp",
				|region: Region<'_, F>| {
					let mut ctx = RegionCtx::new(region, 0);
					let target = ctx.assign_advice(config.common.advice[0], self.target.clone())?;

					ctx.next();
					let mut items = Vec::new();
					for i in 0..self.items.len() {
						let item = self.items[i].clone();
						let assigned_item = ctx.assign_advice(config.common.advice[0], item)?;
						items.push(assigned_item);
						ctx.next();
					}

					Ok((target, items))
				},
			)?;
			let set_chip = SetChipset::new(items, numba);
			let is_zero = set_chip.synthesize(
				&config.common,
				&config.set,
				layouter.namespace(|| "fixed_set"),
			)?;
			layouter.constrain_instance(is_zero.cell(), config.common.instance, 0)?;
			Ok(())
		}
	}

	#[test]
	fn test_is_member() {
		// Testing a target value from the set.
		let set = vec![Fr::from(1), Fr::from(2), Fr::from(3)];
		let target = Fr::from(2);
		let test_chip = TestCircuit::new(set, target);

		let pub_ins = vec![Fr::one()];
		let k = 5;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_not_member() {
		// Testing a target value that is not in the set.
		let set = vec![Fr::from(1), Fr::from(2), Fr::from(4), Fr::from(15), Fr::from(23)];
		let target = Fr::from(12);
		let test_chip = TestCircuit::new(set, target);

		let pub_ins = vec![Fr::zero()];
		let k = 6;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_member_zero() {
		// Testing target value as 0.
		let set = vec![Fr::from(0), Fr::from(4), Fr::from(5), Fr::from(11), Fr::from(13)];
		let target = Fr::from(0);
		let test_chip = TestCircuit::new(set, target);

		let pub_ins = vec![Fr::one()];
		let k = 6;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_member_big() {
		// Testing a big set.
		let set = [(); 1024].map(|_| <Fr as Field>::random(rand::thread_rng())).to_vec();
		let target = set[722].clone();
		let test_chip = TestCircuit::new(set, target);

		let pub_ins = vec![Fr::one()];
		let k = 12;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_member_production() {
		let set = vec![Fr::from(1), Fr::from(2), Fr::from(3)];
		let target = Fr::from(2);
		let test_chip = TestCircuit::new(set, target);

		let k = 5;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::one()]], rng).unwrap();
		assert!(res);
	}
}
