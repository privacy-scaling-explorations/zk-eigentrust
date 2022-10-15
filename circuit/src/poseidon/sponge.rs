use std::marker::PhantomData;

use crate::{
	params::RoundParams,
	poseidon::{PoseidonChip, PoseidonConfig},
};
use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};

#[derive(Clone)]
/// Configuration elements for the circuit are defined here.
struct PoseidonSpongeConfig<const WIDTH: usize> {
	/// Constructs poseidon circuit elements.
	poseidon_config: PoseidonConfig<WIDTH>,
	/// Configures a fixed boolean value for each row of the circuit.
	absorb_selector: Selector,
}

/// Constructs a chip structure for the circuit.
struct PoseidonSpongeChip<F: FieldExt, const WIDTH: usize, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Constructs a cell vector for the inputs.
	inputs: Vec<AssignedCell<F, F>>,
	/// Constructs a phantom data for the parameters.
	_params: PhantomData<P>,
}

impl<F: FieldExt, const WIDTH: usize, P> PoseidonSpongeChip<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Create a new chip.
	fn new() -> Self {
		Self { inputs: Vec::new(), _params: PhantomData }
	}

	/// Make the circuit config.
	fn configure(meta: &mut ConstraintSystem<F>) -> PoseidonSpongeConfig<WIDTH> {
		let poseidon_config = PoseidonChip::<_, WIDTH, P>::configure(meta);
		let absorb_selector = meta.selector();

		meta.create_gate("absorb", |v_cells| {
			let mut exprs = [(); WIDTH].map(|_| Expression::Constant(F::zero()));

			let s = v_cells.query_selector(absorb_selector);
			for i in 0..WIDTH {
				let poseidon_exp = v_cells.query_advice(poseidon_config.state[i], Rotation::prev());
				let sponge_exp = v_cells.query_advice(poseidon_config.state[i], Rotation::cur());
				let next_sponge_exp =
					v_cells.query_advice(poseidon_config.state[i], Rotation::next());
				let diff = next_sponge_exp - (sponge_exp + poseidon_exp);
				exprs[i] = s.clone() * diff;
			}

			exprs
		});

		PoseidonSpongeConfig { poseidon_config, absorb_selector }
	}

	/// Absorb the data in and split it into
	/// chunks of size WIDTH.
	fn load_state(
		columns: [Column<Advice>; WIDTH], region: &mut Region<'_, F>, round: usize,
		prev_state: &[AssignedCell<F, F>],
	) -> Result<[AssignedCell<F, F>; WIDTH], Error> {
		let mut state: [Option<AssignedCell<F, F>>; WIDTH] = [(); WIDTH].map(|_| None);
		for i in 0..WIDTH {
			if let Some(cell) = prev_state.get(i) {
				state[i] = Some(cell.copy_advice(|| "state", region, columns[i], round)?);
			} else {
				state[i] = Some(region.assign_advice(
					|| "state",
					columns[i],
					round,
					|| Value::known(F::zero()),
				)?);
			}
		}
		Ok(state.map(|item| item.unwrap()))
	}

	/// Clones and appends all elements from a slice to the vec.
	fn update(&mut self, inputs: &[AssignedCell<F, F>]) {
		self.inputs.extend_from_slice(inputs);
	}

	/// Squeeze the data out by
	/// permuting until no more chunks are left.
	pub fn squeeze(
		&self, config: &PoseidonSpongeConfig<WIDTH>, mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		assert!(!self.inputs.is_empty());

		let mut state = layouter.assign_region(
			|| "load_chunks",
			|mut region: Region<'_, F>| {
				Self::load_state(config.poseidon_config.state, &mut region, 1, &[])
			},
		)?;

		for (i, chunk) in self.inputs.chunks(WIDTH).enumerate() {
			let inputs = layouter.assign_region(
				|| format!("absorb_{}", i),
				|mut region: Region<'_, F>| {
					let round = 1;
					config.absorb_selector.enable(&mut region, round)?;

					let loaded_chunk =
						Self::load_state(config.poseidon_config.state, &mut region, round, chunk)?;
					let loaded_state = Self::load_state(
						config.poseidon_config.state,
						&mut region,
						round - 1,
						&state,
					)?;

					let next_state = loaded_chunk
						.zip(loaded_state)
						.zip(config.poseidon_config.state)
						.try_map(|((prev_state, pos_state), column)| {
							let sum = prev_state
								.value()
								.and_then(|&s| pos_state.value().map(|&ps| s + ps));
							region.assign_advice(|| "sum", column, round + 1, || sum)
						})?;

					Ok(next_state)
				},
			)?;

			let pos = PoseidonChip::<_, WIDTH, P>::new(inputs);
			state = pos.synthesize(
				config.poseidon_config.clone(),
				layouter.namespace(|| format!("absorb_{}", i)),
			)?;
		}

		Ok(state[0].clone())
	}
}

#[cfg(test)]
mod test {
	use super::{PoseidonSpongeChip, PoseidonSpongeConfig};
	use crate::poseidon::native::sponge::PoseidonSponge;

	use crate::params::{hex_to_field, poseidon_bn254_5x5::Params};

	use halo2wrong::{
		curves::bn256::Fr,
		halo2::{
			circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
			dev::MockProver,
			plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
		},
	};

	type TestPoseidonSponge = PoseidonSponge<Fr, 5, Params>;
	type TestPoseidonSpongeChip = PoseidonSpongeChip<Fr, 5, Params>;

	#[derive(Clone)]
	struct PoseidonTesterConfig {
		sponge: PoseidonSpongeConfig<5>,
		results: Column<Instance>,
	}

	struct PoseidonTester {
		inputs1: [Value<Fr>; 5],
		inputs2: [Value<Fr>; 5],
	}

	impl PoseidonTester {
		fn new(inputs1: [Fr; 5], inputs2: [Fr; 5]) -> Self {
			Self {
				inputs1: inputs1.map(|item| Value::known(item)),
				inputs2: inputs2.map(|item| Value::known(item)),
			}
		}

		fn load_state(
			config: &PoseidonSpongeConfig<5>, region: &mut Region<'_, Fr>, round: usize,
			init_state: [Value<Fr>; 5],
		) -> Result<[AssignedCell<Fr, Fr>; 5], Error> {
			let mut state: [Option<AssignedCell<Fr, Fr>>; 5] = [(); 5].map(|_| None);
			for i in 0..5 {
				state[i] = Some(region.assign_advice(
					|| "state",
					config.poseidon_config.state[i],
					round,
					|| init_state[i],
				)?);
			}
			Ok(state.map(|item| item.unwrap()))
		}
	}

	impl Circuit<Fr> for PoseidonTester {
		type Config = PoseidonTesterConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { inputs1: [Value::unknown(); 5], inputs2: [Value::unknown(); 5] }
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
			let sponge_config = TestPoseidonSpongeChip::configure(meta);
			let results = meta.instance_column();

			meta.enable_equality(results);

			Self::Config { sponge: sponge_config, results }
		}

		fn synthesize(
			&self, config: Self::Config, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let inputs1 = layouter.assign_region(
				|| "load_state1",
				|mut region: Region<'_, Fr>| {
					Self::load_state(&config.sponge, &mut region, 0, self.inputs1)
				},
			)?;

			let inputs2 = layouter.assign_region(
				|| "load_state2",
				|mut region: Region<'_, Fr>| {
					Self::load_state(&config.sponge, &mut region, 0, self.inputs2)
				},
			)?;

			let mut poseidon_sponge = TestPoseidonSpongeChip::new();
			poseidon_sponge.update(&inputs1);
			poseidon_sponge.update(&inputs2);
			let result_state = poseidon_sponge
				.squeeze(&config.sponge, layouter.namespace(|| "poseidon_sponge"))?;

			layouter.constrain_instance(result_state.cell(), config.results, 0)?;
			Ok(())
		}
	}

	#[test]
	fn should_match_native_sponge() {
		// Testing circuit and native sponge equality.
		let inputs1: [Fr; 5] = [
			"0x0000000000000000000000000000000000000000000000000000000000000000",
			"0x0000000000000000000000000000000000000000000000000000000000000001",
			"0x0000000000000000000000000000000000000000000000000000000000000002",
			"0x0000000000000000000000000000000000000000000000000000000000000003",
			"0x0000000000000000000000000000000000000000000000000000000000000004",
		]
		.map(|n| hex_to_field(n));

		let inputs2: [Fr; 5] = [
			"0x0000000000000000000000000000000000000000000000000000000000000005",
			"0x0000000000000000000000000000000000000000000000000000000000000006",
			"0x0000000000000000000000000000000000000000000000000000000000000007",
			"0x0000000000000000000000000000000000000000000000000000000000000008",
			"0x0000000000000000000000000000000000000000000000000000000000000009",
		]
		.map(|n| hex_to_field(n));

		let mut sponge = TestPoseidonSponge::new();
		sponge.update(&inputs1);
		sponge.update(&inputs2);

		let native_result = sponge.squeeze();

		let poseidon_sponge = PoseidonTester::new(inputs1, inputs2);

		let k = 12;
		let prover = MockProver::run(k, &poseidon_sponge, vec![vec![native_result]]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}
}
