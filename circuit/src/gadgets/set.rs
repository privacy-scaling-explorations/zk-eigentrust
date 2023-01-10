use super::common::{CommonChip, CommonConfig};
use halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
	poly::Rotation,
};

#[derive(Clone, Debug)]
/// Configuration elements for the circuit defined here.
pub struct FixedSetConfig {
	/// Constructs is_zero circuit elements.
	is_zero: CommonConfig,
	/// Configures a column for the target.
	target: Column<Advice>,
	/// Configures a fixed column for the items.
	items: Column<Fixed>,
	/// Configures a column for the diffs.
	diffs: Column<Advice>,
	/// Configures a column for the product.
	product: Column<Advice>,
	/// Configures a fixed boolean value for each row of the circuit.
	selector: Selector,
}

/// Constructs individual cells for the configuration elements.
pub struct FixedSetChip<F: FieldExt, const N: usize> {
	/// Constructs items variable for the circuit.
	items: [F; N],
	/// Assigns a cell for the target.
	target: AssignedCell<F, F>,
}

impl<F: FieldExt, const N: usize> FixedSetChip<F, N> {
	/// Create a new chip.
	pub fn new(items: [F; N], target: AssignedCell<F, F>) -> Self {
		FixedSetChip { items, target }
	}

	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> FixedSetConfig {
		let is_zero = CommonChip::configure(meta);
		let target = meta.advice_column();
		let items = meta.fixed_column();
		let diffs = meta.advice_column();
		let product = meta.advice_column();
		let fixed = meta.fixed_column();
		let s = meta.selector();

		meta.enable_equality(target);
		meta.enable_equality(items);
		meta.enable_equality(product);
		meta.enable_constant(fixed);

		meta.create_gate("fixed_set_membership", |v_cells| {
			let _target_exp = v_cells.query_advice(target, Rotation::cur());

			let _item_exp = v_cells.query_fixed(items, Rotation::cur());
			let diff_exp = v_cells.query_advice(diffs, Rotation::cur());

			let product_exp = v_cells.query_advice(product, Rotation::cur());
			let next_product_exp = v_cells.query_advice(product, Rotation::next());

			let s_exp = v_cells.query_selector(s);

			vec![
				// If the difference is equal to 0, that will make the next product equal to 0.
				// Example:
				// product_exp = 1
				// diff_exp = 0
				// Check the constraint (1 * 0 == next_product_exp)
				// That makes next_product_exp = 0
				// => (1 * 0) - 0 == 0
				s_exp.clone() * (product_exp * diff_exp.clone() - next_product_exp),
				// TODO: uncomment this line when the bug is fixed.
				// s_exp * (target_exp - (diff_exp + item_exp)),
			]
		});

		FixedSetConfig { is_zero, target, items, diffs, product, selector: s }
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self, config: FixedSetConfig, mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		let product = layouter.assign_region(
			|| "set_membership",
			|mut region: Region<'_, F>| {
				let mut assigned_product = region.assign_advice_from_constant(
					|| "initial_product",
					config.product,
					0,
					F::one(),
				)?;
				let mut assigned_target =
					self.target.copy_advice(|| "target", &mut region, config.target, 0)?;
				for i in 0..N {
					config.selector.enable(&mut region, i)?;

					let item_value = Value::known(self.items[i]);
					region.assign_fixed(
						|| format!("item_{}", i),
						config.items,
						i,
						|| item_value,
					)?;

					// Calculating difference between given target and item from the set.
					let diff = self.target.value().cloned() - item_value;
					// If the difference is equal to 0, that means the target is in the set and next
					// product will become 0.
					let next_product = assigned_product.value().cloned() * diff;

					region.assign_advice(|| format!("diff_{}", i), config.diffs, i, || diff)?;
					assigned_product = region.assign_advice(
						|| format!("product_{}", i),
						config.product,
						i + 1,
						|| next_product,
					)?;
					assigned_target = assigned_target.copy_advice(
						|| "target",
						&mut region,
						config.target,
						i + 1,
					)?;
				}

				Ok(assigned_product)
			},
		)?;

		let is_zero =
			CommonChip::is_zero(product, &config.is_zero, layouter.namespace(|| "is_member"))?;

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
