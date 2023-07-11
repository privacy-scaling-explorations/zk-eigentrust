use crate::{gadgets::main::IsZeroChipset, Chip, Chipset, CommonConfig, FieldExt, RegionCtx};
use halo2::{
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{ConstraintSystem, Error, Expression, Selector},
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
		//
		// IMPORTANT: For the maximal usage of CommonConfig columns(20 advice + 10 fixed),
		//			  we use the advice column 16 - 19. (17th ~ 20th)
		//

		let selector = meta.selector();

		meta.create_gate("set_membership", |v_cells| {
			let target_exp = v_cells.query_advice(common.advice[16], Rotation::cur());

			let item_exp = v_cells.query_advice(common.advice[17], Rotation::cur());
			let diff_exp = v_cells.query_advice(common.advice[18], Rotation::cur());

			let product_exp = v_cells.query_advice(common.advice[19], Rotation::cur());
			let next_product_exp = v_cells.query_advice(common.advice[19], Rotation::next());

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

				let mut assigned_product = ctx.assign_from_constant(common.advice[19], F::ONE)?;
				let mut assigned_target =
					ctx.copy_assign(common.advice[16], self.target.clone())?;
				for i in 0..self.items.len() {
					ctx.enable(*selector)?;

					let item_value = ctx.copy_assign(common.advice[17], self.items[i].clone())?;

					// Calculating difference between given target and item from the set.
					let diff = self.target.value().cloned() - item_value.value().cloned();
					// If the difference is equal to 0, that means the target is in the set and next
					// product will become 0.
					let next_product = assigned_product.value().cloned() * diff;
					ctx.assign_advice(common.advice[18], diff)?;

					ctx.next();
					assigned_product = ctx.assign_advice(common.advice[19], next_product)?;
					assigned_target = ctx.copy_assign(common.advice[16], assigned_target)?;
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
	pub fn new(main: MainConfig, set_selector: Selector) -> Self {
		Self { main, set_selector }
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

/// A chip for checking item membership in a set of field values
pub struct SetPositionChip<F: FieldExt> {
	/// Constructs items variable for the circuit.
	items: Vec<AssignedCell<F, F>>,
	/// Assigns a cell for the target.
	target: AssignedCell<F, F>,
}

impl<F: FieldExt> SetPositionChip<F> {
	/// Construct a new chip
	pub fn new(items: Vec<AssignedCell<F, F>>, target: AssignedCell<F, F>) -> Self {
		SetPositionChip { items, target }
	}
}

impl<F: FieldExt> Chip<F> for SetPositionChip<F> {
	type Output = AssignedCell<F, F>;

	/// Make the circuit config.
	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector {
		let selector = meta.selector();

		meta.create_gate("set_position_index", |v_cells| {
			//
			// Gate config
			//
			//  |  selector  |     0      |     1      |    2     |     3    |   4   |   5   |
			//  |------------|------------|------------|----------|----------|-------|-------|
			//  |     *      |   target   |    item    |   diff   | diff_inv |  add  |  idx  |

			//
			// Example: set = [1, 2, 3, 4, 5], target = 4
			//
			//  |  selector  |   target   |    item    |   diff    | diff_inv |  add  |  idx  |
			//  |------------|------------|------------|-----------|----------|-------|-------|
			//  |            |            |      	   |           |          |   1   |       |
			//  |     *      |     4      |     1	   |     3     |   3^(-1) |   1   |   0   |
			//  |     *      |     4      |     2      |     2     |   2^(-1) |   1   |   1   |
			//  |     *      |     4      |     3      |     1     |   1^(-1) |   1   |   2   |
			//  |     *      |     4      |     4      |     0     |   1      |   0   |   3   |
			//  |     *      |     4      |     5      |    -1     |  -1^(-1) |   0   |   3   |

			let target_exp = v_cells.query_advice(common.advice[0], Rotation::cur());

			let item_exp = v_cells.query_advice(common.advice[1], Rotation::cur());
			let diff_exp = v_cells.query_advice(common.advice[2], Rotation::cur());
			let diff_inv_exp = v_cells.query_advice(common.advice[3], Rotation::cur());

			let add_prev_exp = v_cells.query_advice(common.advice[4], Rotation::prev());
			let add_exp = v_cells.query_advice(common.advice[4], Rotation::cur());

			let idx_exp = v_cells.query_advice(common.advice[5], Rotation::cur());
			let idx_next_exp = v_cells.query_advice(common.advice[5], Rotation::next());

			let s_exp = v_cells.query_selector(selector);

			let one_exp = Expression::Constant(F::ONE);

			vec![
				// If the difference is equal to 0, that will make the `add` equal to 0.
				// The following `add`s all become 0.

				// diff = target - item
				s_exp.clone() * (target_exp - (diff_exp.clone() + item_exp)),
				// idx_next = idx + add
				s_exp.clone() * (idx_next_exp - (idx_exp + add_exp.clone())),
				// add * (1 - add) = 0
				s_exp.clone() * (add_exp.clone() * (one_exp.clone() - add_exp.clone())),
				// add * (1 - add_prev) = 0
				s_exp.clone() * (add_exp.clone() * (one_exp - add_prev_exp.clone())),
				//
				// base constraint  => if diff = 0 { add = 0 } else { add = 1 }
				//      diff * (1 / diff) = add
				//      diff * diff_inv - add = 0
				//
				// final constraint => if add_prev = 0 { no base constraint check } else { base constraint check }
				//      (diff * diff_inv - add) * add_prev = 0
				//
				s_exp * ((diff_exp * diff_inv_exp - add_exp) * add_prev_exp),
			]
		});

		selector
	}

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, selector: &Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		layouter.assign_region(
			|| "set_position_index",
			|region: Region<'_, F>| {
				let mut ctx = RegionCtx::new(region, 0);

				let mut add_prev_cell = ctx.assign_from_constant(common.advice[4], F::ONE)?;
				ctx.next();

				let mut assigned_idx = ctx.assign_from_constant(common.advice[5], F::ZERO)?;
				let mut assigned_target = ctx.copy_assign(common.advice[0], self.target.clone())?;
				for i in 0..self.items.len() {
					ctx.enable(*selector)?;

					let item_cell = ctx.copy_assign(common.advice[1], self.items[i].clone())?;

					// Calculating difference between given target and item from the set.
					let diff = self.target.value().cloned() - item_cell.value().cloned();
					let diff_cell = ctx.assign_advice(common.advice[2], diff)?;

					let diff_inv = diff.map(|x| x.invert().unwrap_or(F::ONE));
					let diff_inv_cell = ctx.assign_advice(common.advice[3], diff_inv)?;

					// Calculating the "add" value
					let add_value = {
						diff_cell.value().cloned()
							* diff_inv_cell.value().cloned()
							* add_prev_cell.value().cloned()
					};
					add_prev_cell = ctx.assign_advice(common.advice[4], add_value)?;
					let next_idx = assigned_idx.value().cloned() + add_value;

					ctx.next();
					assigned_idx = ctx.assign_advice(common.advice[5], next_idx)?;
					assigned_target = ctx.copy_assign(common.advice[0], assigned_target)?;
				}

				Ok(assigned_idx)
			},
		)
	}
}

/// A chip for selecting item with index in a set of field values
pub struct SelectItemChip<F: FieldExt> {
	/// Constructs items variable for the circuit.
	items: Vec<AssignedCell<F, F>>,
	/// Assigns a cell for the index.
	idx: AssignedCell<F, F>,
}

impl<F: FieldExt> SelectItemChip<F> {
	/// Construct a new chip
	pub fn new(items: Vec<AssignedCell<F, F>>, idx: AssignedCell<F, F>) -> Self {
		SelectItemChip { items, idx }
	}
}

impl<F: FieldExt> Chip<F> for SelectItemChip<F> {
	type Output = AssignedCell<F, F>;

	/// Make the circuit config.
	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector {
		let selector = meta.selector();

		meta.create_gate("select_item_with_idx", |v_cells| {
			//
			// Gate config
			//
			//  |  selector  |    0    |   0(f)   |   1     |     2     |   3    |   4   |   5   |  6   |
			//  |------------|---------|----------|---------|-----------|--------|-------|-------|------|
			//  |     *      |   idx   |    id    |  diff   |  diff_inv | select |  elem |  add  | item |

			//
			// Example: set = [1, 2, 3, 4, 5], idx = 2
			//
			//  |  selector  |   idx   |   id   |   diff    | diff_inv  | select |  elem |  add  | item  |
			//  |------------|---------|--------|-----------|-----------|--------|-------|-------|-------|
			//  |            |         |        |           |           |        |       |       |   0   |
			//  |     *      |    2    |    0   |     2     |   2^(-1)  |   0    |   1   |   0   |   0   |
			//  |     *      |    2    |    1   |     1     |   1^(-1)  |   0    |   2   |   0   |   0   |
			//  |     *      |    2    |    2   |     0     |   1       |   1    |   3   |   3   |   3   |
			//  |     *      |    2    |    3   |    -1     |  -1^(-1)  |   0    |   4   |   0   |   3   |
			//  |     *      |    2    |    4   |    -2     |  -2^(-1)  |   0    |   5   |   0   |   3   |
			//
			// NOTE: In the chip implementation, we use fixed column for "id" column.
			//       The reason is that it is cheaper than using advice column.

			let idx_exp = v_cells.query_advice(common.advice[0], Rotation::cur());
			let id_exp = v_cells.query_fixed(common.fixed[0], Rotation::cur());
			let diff_exp = v_cells.query_advice(common.advice[1], Rotation::cur());
			let diff_inv_exp = v_cells.query_advice(common.advice[2], Rotation::cur());
			let select_exp = v_cells.query_advice(common.advice[3], Rotation::cur());
			let elem_exp = v_cells.query_advice(common.advice[4], Rotation::cur());
			let add_exp = v_cells.query_advice(common.advice[5], Rotation::cur());

			let item_prev_exp = v_cells.query_advice(common.advice[6], Rotation::prev());
			let item_exp = v_cells.query_advice(common.advice[6], Rotation::cur());

			let s_exp = v_cells.query_selector(selector);

			let one_exp = Expression::Constant(F::ONE);

			vec![
				// If the difference is equal to 0, that will make the `select` equal to 1.

				// diff = idx(target) - id(elem)
				s_exp.clone() * (idx_exp - (diff_exp.clone() + id_exp)),
				// select * (1 - select) = 0
				s_exp.clone() * (select_exp.clone() * (one_exp.clone() - select_exp.clone())),
				//
				// if diff = 0 { select = 1 } else { select = 0 }
				//      diff * (1 / diff) = 1 - select
				//      1 - select - diff * diff_inv = 0
				//
				s_exp.clone() * (one_exp - select_exp.clone() - diff_exp * diff_inv_exp),
				// add = select * elem
				s_exp.clone() * (add_exp.clone() - (select_exp * elem_exp)),
				// item = add + item_prev
				s_exp * (item_exp - (item_prev_exp + add_exp)),
			]
		});

		selector
	}

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, selector: &Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		layouter.assign_region(
			|| "select_item_with_idx",
			|region: Region<'_, F>| {
				let mut ctx = RegionCtx::new(region, 0);

				let mut item_prev_cell = ctx.assign_from_constant(common.advice[6], F::ZERO)?;
				ctx.next();

				let mut assigned_item = ctx.assign_from_constant(common.advice[6], F::ZERO)?;
				let mut assigned_target_idx =
					ctx.copy_assign(common.advice[0], self.idx.clone())?;
				for i in 0..self.items.len() {
					ctx.enable(*selector)?;

					let id = F::from(i as u64);
					ctx.assign_fixed(common.fixed[0], id)?;

					// Calculating difference between given target idx and id of element from the set.
					let diff = self.idx.value().cloned() - Value::known(id);
					let diff_cell = ctx.assign_advice(common.advice[1], diff)?;

					// Calculating the inverse of difference
					let diff_inverse = diff.map(|x| x.invert().unwrap_or(F::ONE));
					let diff_inverse_cell = ctx.assign_advice(common.advice[2], diff_inverse)?;

					// Calculating the "select" value
					let select_value = Value::known(F::ONE)
						- diff_cell.value().cloned() * diff_inverse_cell.value().cloned();
					let select_cell = ctx.assign_advice(common.advice[3], select_value)?;

					// Assign set element
					let elem_cell = ctx.copy_assign(common.advice[4], self.items[i].clone())?;

					// Calculating the "add" value
					let add_value = select_cell.value().cloned() * elem_cell.value().cloned();
					let add_cell = ctx.assign_advice(common.advice[5], add_value)?;

					// Calculating the "item"
					let item_value = item_prev_cell.value().cloned() + add_cell.value().cloned();
					assigned_item = ctx.assign_advice(common.advice[6], item_value)?;

					ctx.next();
					assigned_target_idx = ctx.copy_assign(common.advice[0], assigned_target_idx)?;
					item_prev_cell = assigned_item.clone();
				}

				Ok(assigned_item)
			},
		)
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
			let set = SetConfig::new(main, set_selector);

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
		let k = 5;
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
		let k = 5;
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

	#[derive(Clone)]
	struct TestSetPositionConfig {
		common: CommonConfig,
		set_pos_selector: Selector,
	}

	#[derive(Clone)]
	struct TestSetPositionCircuit<F: FieldExt> {
		items: Vec<Value<F>>,
		target: Value<F>,
	}

	impl<F: FieldExt> TestSetPositionCircuit<F> {
		fn new(items: Vec<F>, target: F) -> Self {
			Self {
				items: items.into_iter().map(|x| Value::known(x)).collect(),
				target: Value::known(target),
			}
		}
	}

	impl<F: FieldExt> Circuit<F> for TestSetPositionCircuit<F> {
		type Config = TestSetPositionConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self {
				items: self.items.clone().into_iter().map(|_| Value::unknown()).collect(),
				target: Value::unknown(),
			}
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestSetPositionConfig {
			let common = CommonConfig::new(meta);
			let set_pos_selector = SetPositionChip::configure(&common, meta);

			TestSetPositionConfig { common, set_pos_selector }
		}

		fn synthesize(
			&self, config: TestSetPositionConfig, mut layouter: impl Layouter<F>,
		) -> Result<(), Error> {
			let (target, items) = layouter.assign_region(
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
			let set_pos_chip = SetPositionChip::new(items, target);
			let idx = set_pos_chip.synthesize(
				&config.common,
				&config.set_pos_selector,
				layouter.namespace(|| "set_position"),
			)?;
			layouter.constrain_instance(idx.cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	#[test]
	fn test_position_index() {
		// Testing a target value from the set.
		let set = vec![Fr::from(1), Fr::from(2), Fr::from(3)];
		let target_index = 2;
		let target = set[target_index].clone();
		let test_chip = TestSetPositionCircuit::new(set, target);

		let pub_ins = vec![Fr::from(target_index as u64)];
		let k = 5;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_no_position_index() {
		// Testing a target value that is not in the set.
		let set = vec![Fr::from(1), Fr::from(2), Fr::from(4), Fr::from(15), Fr::from(23)];
		let target = Fr::from(12);
		let test_chip = TestSetPositionCircuit::new(set, target);

		let pub_ins = vec![Fr::from(5)];
		let k = 5;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_big_set_position_index() {
		// Testing a big set.
		let set = [(); 1024].map(|_| <Fr as Field>::random(rand::thread_rng())).to_vec();
		let target_index = 722;
		let target = set[target_index].clone();
		let test_chip = TestSetPositionCircuit::new(set, target);

		let pub_ins = vec![Fr::from(target_index as u64)];
		let k = 12;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_position_index_production() {
		let set = vec![Fr::from(1), Fr::from(2), Fr::from(3)];
		let target_index = 1;
		let target = set[target_index].clone();
		let test_chip = TestSetPositionCircuit::new(set, target);

		let k = 5;
		let pub_ins = vec![Fr::from(target_index as u64)];
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, test_chip, &[&pub_ins], rng).unwrap();
		assert!(res);
	}

	#[derive(Clone)]
	struct TestSelectItemConfig {
		common: CommonConfig,
		select_item_selector: Selector,
	}

	#[derive(Clone)]
	struct TestSelectItemCircuit<F: FieldExt> {
		items: Vec<Value<F>>,
		idx: Value<F>,
	}

	impl<F: FieldExt> TestSelectItemCircuit<F> {
		fn new(items: Vec<F>, idx: F) -> Self {
			Self {
				items: items.into_iter().map(|x| Value::known(x)).collect(),
				idx: Value::known(idx),
			}
		}
	}

	impl<F: FieldExt> Circuit<F> for TestSelectItemCircuit<F> {
		type Config = TestSelectItemConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self {
				items: self.items.clone().into_iter().map(|_| Value::unknown()).collect(),
				idx: Value::unknown(),
			}
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestSelectItemConfig {
			let common = CommonConfig::new(meta);
			let select_item_selector = SelectItemChip::configure(&common, meta);

			TestSelectItemConfig { common, select_item_selector }
		}

		fn synthesize(
			&self, config: TestSelectItemConfig, mut layouter: impl Layouter<F>,
		) -> Result<(), Error> {
			let (idx, items) = layouter.assign_region(
				|| "temp",
				|region: Region<'_, F>| {
					let mut ctx = RegionCtx::new(region, 0);
					let idx = ctx.assign_advice(config.common.advice[0], self.idx.clone())?;

					ctx.next();
					let mut items = Vec::new();
					for i in 0..self.items.len() {
						let item = self.items[i].clone();
						let assigned_item = ctx.assign_advice(config.common.advice[0], item)?;
						items.push(assigned_item);
						ctx.next();
					}

					Ok((idx, items))
				},
			)?;
			let select_item_chip = SelectItemChip::new(items, idx);
			let idx = select_item_chip.synthesize(
				&config.common,
				&config.select_item_selector,
				layouter.namespace(|| "select_item"),
			)?;
			layouter.constrain_instance(idx.cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	#[test]
	fn test_select_item() {
		// Testing a normal index.
		let set = vec![Fr::from(1), Fr::from(2), Fr::from(3)];
		let target_index = 1;
		let target_item = set[target_index].clone();
		let test_chip = TestSelectItemCircuit::new(set, Fr::from(target_index as u64));

		let pub_ins = vec![Fr::from(target_item)];
		let k = 5;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_no_item_at_index() {
		// Testing a index that is out of original set length
		// In this case, the output of circuit is zero. (F::ZERO)
		let set = vec![Fr::from(1), Fr::from(2), Fr::from(4), Fr::from(15), Fr::from(23)];
		let idx = set.len() + 1;

		let test_chip = TestSelectItemCircuit::new(set, Fr::from(idx as u64));

		let pub_ins = vec![Fr::zero()];
		let k = 5;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_big_set_select_item() {
		// Testing a big set.
		let set = [(); 1024].map(|_| <Fr as Field>::random(rand::thread_rng())).to_vec();
		let target_index = 722;
		let target_item = set[target_index].clone();
		let test_chip = TestSelectItemCircuit::new(set, Fr::from(target_index as u64));

		let pub_ins = vec![target_item];
		let k = 12;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_select_item_production() {
		let set = vec![Fr::from(1), Fr::from(2), Fr::from(3)];
		let target_index = 1;
		let target_item = set[target_index].clone();
		let test_chip = TestSelectItemCircuit::new(set, Fr::from(target_index as u64));

		let k = 5;
		let pub_ins = vec![target_item];
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, test_chip, &[&pub_ins], rng).unwrap();
		assert!(res);
	}
}
