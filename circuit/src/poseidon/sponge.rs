use super::copy_state;
use crate::{
	params::RoundParams,
	poseidon::{PoseidonChipset, PoseidonConfig},
	Chip, Chipset, CommonConfig,
};
use halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};
use std::marker::PhantomData;

/// A chip for absorbing the previous poseidon state
pub struct AbsorbChip<F: FieldExt, const WIDTH: usize> {
	prev_state: [AssignedCell<F, F>; WIDTH],
	state: [AssignedCell<F, F>; WIDTH],
}

impl<F: FieldExt, const WIDTH: usize> AbsorbChip<F, WIDTH> {
	/// Constructor for a chip
	pub fn new(
		prev_state: [AssignedCell<F, F>; WIDTH], state: [AssignedCell<F, F>; WIDTH],
	) -> Self {
		Self { prev_state, state }
	}
}

impl<F: FieldExt, const WIDTH: usize> Chip<F> for AbsorbChip<F, WIDTH> {
	type Output = [AssignedCell<F, F>; WIDTH];

	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector {
		let absorb_selector = meta.selector();

		meta.create_gate("absorb", |v_cells| {
			let mut exprs = [(); WIDTH].map(|_| Expression::Constant(F::zero()));

			let s = v_cells.query_selector(absorb_selector);
			for i in 0..WIDTH {
				let poseidon_exp = v_cells.query_advice(common.advice[i], Rotation::prev());
				let sponge_exp = v_cells.query_advice(common.advice[i], Rotation::cur());
				let next_sponge_exp = v_cells.query_advice(common.advice[i], Rotation::next());
				let diff = next_sponge_exp - (sponge_exp + poseidon_exp);
				exprs[i] = s.clone() * diff;
			}

			exprs
		});

		absorb_selector
	}

	fn synthesize(
		self, common: &CommonConfig, selector: &Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		layouter.assign_region(
			|| "absorb",
			|mut region: Region<'_, F>| {
				let round = 1;
				selector.enable(&mut region, round)?;

				// Load previous Poseidon state
				let loaded_state = copy_state(common, &mut region, round - 1, &self.prev_state)?;

				// Load next chunk
				let loaded_chunk = copy_state(common, &mut region, round, &self.state)?;

				// Calculate the next state to permute
				let columns = common.advice[0..WIDTH].try_into().unwrap();
				let next_state = loaded_chunk.zip(loaded_state).zip(columns).try_map(
					|((chunk_state, pos_state), column)| {
						let sum =
							chunk_state.value().and_then(|&s| pos_state.value().map(|&ps| s + ps));
						region.assign_advice(|| "sum", column, round + 1, || sum)
					},
				)?;

				Ok(next_state)
			},
		)
	}
}

#[derive(Clone, Debug)]
/// Selectors for poseidon sponge
pub struct PoseidonSpongeConfig {
	poseidon: PoseidonConfig,
	absorb_selector: Selector,
}

impl PoseidonSpongeConfig {
	/// Constructs a new config
	pub fn new(poseidon: PoseidonConfig, absorb_selector: Selector) -> Self {
		Self { poseidon, absorb_selector }
	}
}

/// Constructs a chip structure for the circuit.
pub struct PoseidonSpongeChipset<F: FieldExt, const WIDTH: usize, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Constructs a cell vector for the inputs.
	inputs: Vec<AssignedCell<F, F>>,
	/// Constructs a phantom data for the parameters.
	_params: PhantomData<P>,
}

impl<F: FieldExt, const WIDTH: usize, P> PoseidonSpongeChipset<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Create a new chip.
	pub fn new() -> Self {
		Self { inputs: Vec::new(), _params: PhantomData }
	}

	/// Clones and appends all elements from a slice to the vec.
	pub fn update(&mut self, inputs: &[AssignedCell<F, F>]) {
		self.inputs.extend_from_slice(inputs);
	}
}

impl<F: FieldExt, const WIDTH: usize, P> Chipset<F> for PoseidonSpongeChipset<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	type Config = PoseidonSpongeConfig;
	type Output = AssignedCell<F, F>;

	/// Squeeze the data out by
	/// permuting until no more chunks are left.
	fn synthesize(
		self, common: &CommonConfig, config: &PoseidonSpongeConfig, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		assert!(!self.inputs.is_empty());

		let zero_state = layouter.assign_region(
			|| "load_initial_state",
			|mut region: Region<'_, F>| {
				let mut state: [Option<AssignedCell<F, F>>; WIDTH] = [(); WIDTH].map(|_| None);
				for i in 0..WIDTH {
					state[i] = Some(region.assign_advice(
						|| "state",
						common.advice[i],
						0,
						|| Value::known(F::zero()),
					)?);
				}
				Ok(state.map(|item| item.unwrap()))
			},
		)?;

		let mut state = zero_state.clone();
		for (i, chunk) in self.inputs.chunks(WIDTH).enumerate() {
			let mut curr_chunk = zero_state.clone();
			for j in 0..chunk.len() {
				curr_chunk[j] = chunk[j].clone();
			}

			let absorb = AbsorbChip::new(state, curr_chunk);
			let inputs = absorb.synthesize(
				common,
				&config.absorb_selector,
				layouter.namespace(|| format!("absorb_{}", i)),
			)?;

			let pos = PoseidonChipset::<_, WIDTH, P>::new(inputs);
			state = pos.synthesize(
				common,
				&config.poseidon,
				layouter.namespace(|| format!("poseidon_permute_{}", i)),
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

	use halo2::{
		circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::bn256::Fr,
		plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
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
