use super::is_zero::{IsZeroChip, IsZeroConfig};
use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
	poly::Rotation,
};

#[derive(Clone)]
pub struct FixedSetConfig {
	is_zero: IsZeroConfig,
	target: Column<Advice>,
	items: Column<Fixed>,
	diffs: Column<Advice>,
	product: Column<Advice>,
	temp: Column<Fixed>,
	selector: Selector,
}

pub struct FixedSetChip<F: FieldExt, const N: usize> {
	items: [Value<F>; N],
	target: AssignedCell<F, F>,
}

impl<F: FieldExt, const N: usize> FixedSetChip<F, N> {
	pub fn new(items: [Value<F>; N], target: AssignedCell<F, F>) -> Self {
		FixedSetChip { items, target }
	}

	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> FixedSetConfig {
		let is_zero = IsZeroChip::configure(meta);
		let target = meta.advice_column();
		let items = meta.fixed_column();
		let diffs = meta.advice_column();
		let product = meta.advice_column();
		let temp = meta.fixed_column();
		let s = meta.selector();

		meta.enable_equality(target);
		meta.enable_equality(temp);
		meta.enable_equality(product);

		meta.create_gate("fixed_set_membership", |v_cells| {
			let target_exp = v_cells.query_advice(target, Rotation::cur());
			let next_target_exp = v_cells.query_advice(target, Rotation::next());

			let item_exp = v_cells.query_fixed(items, Rotation::cur());
			let diff_exp = v_cells.query_advice(diffs, Rotation::cur());

			let product_exp = v_cells.query_advice(product, Rotation::cur());
			let next_product_exp = v_cells.query_advice(product, Rotation::next());

			let s_exp = v_cells.query_selector(s);

			vec![
				s_exp.clone() * (product_exp * diff_exp.clone() - next_product_exp),
				s_exp.clone() * (diff_exp + item_exp - target_exp.clone()),
				// Every target is the same
				s_exp * (next_target_exp - target_exp),
			]
		});

		FixedSetConfig {
			is_zero,
			target,
			items,
			diffs,
			product,
			temp,
			selector: s,
		}
	}

	pub fn synthesize(
		&self,
		config: FixedSetConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		// Make the initial product to be one. We have to enforce it by assigning it to
		// the fixed column.
		let initial_product = layouter.assign_region(
			|| "initial_product",
			|mut region: Region<'_, F>| {
				region.assign_fixed(
					|| "product_initial",
					config.temp,
					0,
					|| Value::known(F::one()),
				)
			},
		)?;
		let product = layouter.assign_region(
			|| "set_membership_product",
			|mut region: Region<'_, F>| {
				let mut assigned_product =
					initial_product.copy_advice(|| "product_0", &mut region, config.product, 0)?;
				let mut assigned_target =
					self.target
						.copy_advice(|| "target", &mut region, config.target, 0)?;
				for i in 0..N {
					config.selector.enable(&mut region, i)?;

					let assigned_item = region.assign_fixed(
						|| format!("item_{}", i),
						config.items,
						i,
						|| self.items[i],
					)?;

					let diff = assigned_target.value().cloned() - assigned_item.value();
					let next_product = assigned_product.value().cloned() * diff;

					region.assign_advice(|| format!("diff_{}", i), config.diffs, i, || diff)?;
					assigned_product = region.assign_advice(
						|| format!("product_{}", i),
						config.product,
						i + 1,
						|| next_product,
					)?;
					assigned_target =
						self.target
							.copy_advice(|| "target", &mut region, config.target, i + 1)?;
				}

				Ok(assigned_product)
			},
		)?;

		let is_zero_chip = IsZeroChip::new(product);
		let is_zero = is_zero_chip.synthesize(config.is_zero, layouter)?;

		Ok(is_zero)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use halo2wrong::{
		curves::bn256::Fr,
		halo2::{
			circuit::SimpleFloorPlanner,
			dev::MockProver,
			plonk::{Circuit, Instance},
		},
	};

	#[derive(Clone)]
	struct TestConfig {
		set: FixedSetConfig,
		pub_ins: Column<Instance>,
		temp: Column<Advice>,
	}

	#[derive(Clone)]
	struct TestCircuit<F: FieldExt> {
		items: [Value<F>; 3],
		target: Value<F>,
	}

	impl<F: FieldExt> TestCircuit<F> {
		fn new(items: [F; 3], target: F) -> Self {
			Self {
				items: items.map(|v| Value::known(v)),
				target: Value::known(target),
			}
		}
	}

	impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
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

			TestConfig {
				set: fixed_set,
				pub_ins: instance,
				temp,
			}
		}

		fn synthesize(
			&self,
			config: TestConfig,
			mut layouter: impl Layouter<F>,
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
		let set = [Fr::from(1), Fr::from(2), Fr::from(3)];
		let target = Fr::from(2);
		let test_chip = TestCircuit::new(set, target);

		let pub_ins = vec![Fr::one()];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}
}
