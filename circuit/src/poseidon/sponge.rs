use crate::{
	gadgets::absorb::AbsorbChip,
	params::RoundParams,
	poseidon::{PoseidonChipset, PoseidonConfig},
	Chip, Chipset, CommonConfig, FieldExt, RegionCtx,
};
use halo2::{
	circuit::{AssignedCell, Layouter, Region},
	plonk::{Error, Selector},
};
use std::marker::PhantomData;

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

#[derive(Clone, Debug)]
/// Constructs a chip structure for the circuit.
pub struct PoseidonSpongeChipset<F: FieldExt, const WIDTH: usize, P>
where
	P: RoundParams<F, WIDTH>,
{
	state: [AssignedCell<F, F>; WIDTH],
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
	pub fn new(initial_state: [AssignedCell<F, F>; WIDTH]) -> Self {
		Self { state: initial_state, inputs: Vec::new(), _params: PhantomData }
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
	type Output = [AssignedCell<F, F>; WIDTH];

	/// Squeeze the data out by
	/// permuting until no more chunks are left.
	fn synthesize(
		self, common: &CommonConfig, config: &PoseidonSpongeConfig, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		assert!(!self.inputs.is_empty());

		let mut state = self.state.clone();
		for (i, chunk) in self.inputs.chunks(WIDTH).enumerate() {
			let mut curr_chunk_opt: [Option<AssignedCell<F, F>>; WIDTH] = [(); WIDTH].map(|_| None);
			for j in 0..chunk.len() {
				curr_chunk_opt[j] = Some(chunk[j].clone());
			}
			let curr_chunk = curr_chunk_opt.map(|x| x.unwrap());

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

		Ok(state)
	}
}

/// Sponge implementation that perserves its state
#[derive(Clone, Debug)]
pub struct StatefulSpongeChipset<F: FieldExt, const WIDTH: usize, P>
where
	P: RoundParams<F, WIDTH>,
{
	chipset: PoseidonSpongeChipset<F, WIDTH, P>,
}

impl<F: FieldExt, const WIDTH: usize, P> StatefulSpongeChipset<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Initialise the sponge
	pub fn init(common: &CommonConfig, mut layouter: impl Layouter<F>) -> Result<Self, Error> {
		let zero_state = layouter.assign_region(
			|| "load_initial_state",
			|region: Region<'_, F>| {
				let mut ctx = RegionCtx::new(region, 0);

				let mut state: [Option<AssignedCell<F, F>>; WIDTH] = [(); WIDTH].map(|_| None);
				for i in 0..WIDTH {
					let zero_asgn = ctx.assign_from_constant(common.advice[i], F::ZERO)?;
					state[i] = Some(zero_asgn);
				}
				Ok(state.map(|item| item.unwrap()))
			},
		)?;
		let pos = PoseidonSpongeChipset::new(zero_state);
		Ok(Self { chipset: pos })
	}

	/// Clones and appends all elements from a slice to the vec.
	pub fn update(&mut self, inputs: &[AssignedCell<F, F>]) {
		self.chipset.update(inputs);
	}

	/// Squeeze the data out by
	/// permuting until no more chunks are left.
	pub fn squeeze(
		&mut self, common: &CommonConfig, config: &PoseidonSpongeConfig, layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		let res = self.chipset.clone().synthesize(common, config, layouter)?;
		let ret_value = res[0].clone();
		self.chipset = PoseidonSpongeChipset::new(res);
		Ok(ret_value)
	}
}

#[cfg(test)]
mod test {
	use super::{AbsorbChip, PoseidonSpongeChipset, PoseidonSpongeConfig};
	use crate::{
		poseidon::{
			native::sponge::PoseidonSponge, FullRoundChip, PartialRoundChip, PoseidonConfig,
		},
		Chip, Chipset, CommonConfig, RegionCtx,
	};

	use crate::params::{hex_to_field, poseidon_bn254_5x5::Params};

	use halo2::{
		circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::bn256::Fr,
		plonk::{Circuit, ConstraintSystem, Error},
	};

	type TestPoseidonSponge = PoseidonSponge<Fr, 5, Params>;
	type TestPoseidonSpongeChipset = PoseidonSpongeChipset<Fr, 5, Params>;
	type FrChip = FullRoundChip<Fr, 5, Params>;
	type PrChip = PartialRoundChip<Fr, 5, Params>;

	#[derive(Clone)]
	struct PoseidonTesterConfig {
		common: CommonConfig,
		sponge: PoseidonSpongeConfig,
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
	}

	impl Circuit<Fr> for PoseidonTester {
		type Config = PoseidonTesterConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { inputs1: [Value::unknown(); 5], inputs2: [Value::unknown(); 5] }
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
			let common = CommonConfig::new(meta);
			let absorb_selector = AbsorbChip::<_, 5>::configure(&common, meta);
			let pr_selector = PrChip::configure(&common, meta);
			let fr_selector = FrChip::configure(&common, meta);
			let poseidon = PoseidonConfig::new(fr_selector, pr_selector);
			let sponge = PoseidonSpongeConfig::new(poseidon, absorb_selector);

			Self::Config { common, sponge }
		}

		fn synthesize(
			&self, config: Self::Config, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let zero_state = layouter.assign_region(
				|| "load_initial_state",
				|region: Region<'_, Fr>| {
					let mut ctx = RegionCtx::new(region, 0);

					let mut state: [Option<AssignedCell<Fr, Fr>>; 5] = [(); 5].map(|_| None);
					for i in 0..5 {
						let zero_asgn =
							ctx.assign_from_constant(config.common.advice[i], Fr::zero())?;
						state[i] = Some(zero_asgn);
					}
					Ok(state.map(|item| item.unwrap()))
				},
			)?;

			let inputs1 = layouter.assign_region(
				|| "load_state1",
				|region: Region<'_, Fr>| {
					let mut ctx = RegionCtx::new(region, 0);
					let mut state: [Option<AssignedCell<Fr, Fr>>; 5] = [(); 5].map(|_| None);
					for i in 0..5 {
						let val = self.inputs1[i].clone();
						let asgn_val = ctx.assign_advice(config.common.advice[i], val)?;
						state[i] = Some(asgn_val);
					}
					Ok(state.map(|item| item.unwrap()))
				},
			)?;

			let inputs2 = layouter.assign_region(
				|| "load_state2",
				|region: Region<'_, Fr>| {
					let mut ctx = RegionCtx::new(region, 0);
					let mut state: [Option<AssignedCell<Fr, Fr>>; 5] = [(); 5].map(|_| None);
					for i in 0..5 {
						let val = self.inputs2[i].clone();
						let asgn_val = ctx.assign_advice(config.common.advice[i], val)?;
						state[i] = Some(asgn_val);
					}
					Ok(state.map(|item| item.unwrap()))
				},
			)?;

			let mut poseidon_sponge = TestPoseidonSpongeChipset::new(zero_state);
			poseidon_sponge.update(&inputs1);
			poseidon_sponge.update(&inputs2);
			let result_state = poseidon_sponge.synthesize(
				&config.common,
				&config.sponge,
				layouter.namespace(|| "poseidon_sponge"),
			)?;

			layouter.constrain_instance(result_state[0].cell(), config.common.instance, 0)?;
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
