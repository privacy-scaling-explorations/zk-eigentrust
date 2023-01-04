use super::common::{CommonChip, CommonConfig};
use halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
	poly::Rotation,
};

/// Constructs individual cells for the configuration elements.
pub struct FixedSetChip<F: FieldExt, const N: usize> {
	/// Constructs items variable for the circuit.
	items: [AssignedCell<F, F>; N],
	/// Assigns a cell for the target.
	target: AssignedCell<F, F>,
}

impl<F: FieldExt, const N: usize> FixedSetChip<F, N> {
	pub fn new(items: [AssignedCell<F, F>; N], target: AssignedCell<F, F>) -> Self {
		FixedSetChip { items, target }
	}
}

impl<F: FieldExt, const N: usize> Chip<F> for FixedSetChip<F, N> {
	type Output = AssignedCell<F, F>;

	/// Make the circuit config.
	fn configure(common: CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector {
		let selector = meta.selector();

		meta.create_gate("fixed_set_membership", |v_cells| {
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
		&self, config: CommonConfig, selector: Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		layouter.assign_region(
			|| "set_membership",
			|mut region: Region<'_, F>| {
				let mut assigned_product = region.assign_advice_from_constant(
					|| "initial_product",
					common.advice[3],
					0,
					F::one(),
				)?;
				let mut assigned_target =
					self.target.copy_advice(|| "target", &mut region, common.advice[0], 0)?;
				for i in 0..N {
					selector.enable(&mut region, i)?;

					let item_value = region.assign_advice(
						|| format!("item_{}", i),
						common.advice[1],
						i,
						|| Value::known(self.items[i]),
					)?;

					// Calculating difference between given target and item from the set.
					let diff = self.target.value().cloned() - item_value.value().cloned();
					// If the difference is equal to 0, that means the target is in the set and next
					// product will become 0.
					let next_product = assigned_product.value().cloned() * diff;

					region.assign_advice(|| format!("diff_{}", i), common.advice[2], i, || diff)?;
					assigned_product = region.assign_advice(
						|| format!("product_{}", i),
						common.advice[3],
						i + 1,
						|| next_product,
					)?;
					assigned_target = assigned_target.copy_advice(
						|| "target",
						&mut region,
						common.advice[0],
						i + 1,
					)?;
				}

				Ok(assigned_product)
			},
		)
	}
}

struct FixedSetConfig {
	is_zero_selector: Selector,
	fixed_set_selector: Selector,
}

struct FixedSetChipset<F: FieldExt, const N: usize> {
	/// Constructs items variable for the circuit.
	items: [AssignedCell<F, F>; N],
	/// Assigns a cell for the target.
	target: AssignedCell<F, F>,
}

impl<F: FieldExt, const N: usize> FixedSetChipset<F, N> {
	pub fn new(items: [AssignedCell<F, F>; N], target: AssignedCell<F, F>) -> Self {
		FixedSetChipset { items, target }
	}
}

impl<F: FieldExt, const N: usize> Chipset<F> for FixedSetChipset<F, N> {
	type Config = FixedSetConfig;
	type Output = AssignedCell<F, F>;

	fn synthesize(
		&self, common: CommonConfig, config: Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		let fixed_set_chip = FixedSetChip::new(self.items, self.target);
		let res = fixed_set_chip.synthesize(
			common,
			config.fixed_set_selector,
			layouter.namespace(|| "fixed_set_membership"),
		)?;

		let is_zero_chip = IsZeroChip::new(res);
		let is_zero = is_zero_chip.synthesize(
			common,
			config.is_zero_selector,
			layouter.namespace(|| "is_member"),
		)?;

		Ok(is_zero)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::utils::{generate_params, prove_and_verify};
	use halo2::{
		arithmetic::Field,
		circuit::{SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::bn256::{Bn256, Fr},
		plonk::{Circuit, Instance},
	};

	#[derive(Clone)]
	struct TestConfig {
		set: FixedSetConfig,
		pub_ins: Column<Instance>,
		temp: Column<Advice>,
	}

	#[derive(Clone)]
	struct TestCircuit<F: FieldExt, const N: usize> {
		items: [F; N],
		target: Value<F>,
	}

	impl<F: FieldExt, const N: usize> TestCircuit<F, N> {
		fn new(items: [F; N], target: F) -> Self {
			Self { items, target: Value::known(target) }
		}
	}

	impl<F: FieldExt, const N: usize> Circuit<F> for TestCircuit<F, N> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
			let fixed_set = FixedSetChip::<F, 3>::configure(meta);
			let temp = meta.advice_column();
			let instance = meta.instance_column();

			meta.enable_equality(instance);
			meta.enable_equality(temp);

			TestConfig { set: fixed_set, pub_ins: instance, temp }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<F>,
		) -> Result<(), Error> {
			let numba = layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, F>| {
					region.assign_advice(|| "temp_x", config.temp, 0, || self.target)
				},
			)?;
			let fixed_set_chip = FixedSetChip::new(self.items, numba);
			let is_zero =
				fixed_set_chip.synthesize(config.set, layouter.namespace(|| "fixed_set"))?;
			layouter.constrain_instance(is_zero.cell(), config.pub_ins, 0)?;
			Ok(())
		}
	}

	#[test]
	fn test_is_member() {
		// Testing a target value from the set.
		let set = [Fr::from(1), Fr::from(2), Fr::from(3)];
		let target = Fr::from(2);
		let test_chip = TestCircuit::new(set, target);

		let pub_ins = vec![Fr::one()];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_not_member() {
		// Testing a target value that is not in the set.
		let set = [Fr::from(1), Fr::from(2), Fr::from(4), Fr::from(15), Fr::from(23)];
		let target = Fr::from(12);
		let test_chip = TestCircuit::new(set, target);

		let pub_ins = vec![Fr::zero()];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_member_zero() {
		// Testing target value as 0.
		let set = [Fr::from(0), Fr::from(4), Fr::from(5), Fr::from(11), Fr::from(13)];
		let target = Fr::from(0);
		let test_chip = TestCircuit::new(set, target);

		let pub_ins = vec![Fr::one()];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_member_big() {
		// Testing a big set.
		let set = [(); 1024].map(|_| <Fr as Field>::random(rand::thread_rng()));
		let target = set[722].clone();
		let test_chip = TestCircuit::new(set, target);

		let pub_ins = vec![Fr::one()];
		let k = 11;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_member_production() {
		let set = [Fr::from(1), Fr::from(2), Fr::from(3)];
		let target = Fr::from(2);
		let test_chip = TestCircuit::new(set, target);

		let k = 4;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::one()]], rng).unwrap();
		assert!(res);
	}
}
