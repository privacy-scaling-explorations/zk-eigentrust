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
	pub inputs: Vec<AssignedCell<F, F>>,
	/// Default value to fill in the input
	default: AssignedCell<F, F>,
	/// Constructs a phantom data for the parameters.
	_params: PhantomData<P>,
}

impl<F: FieldExt, const WIDTH: usize, P> PoseidonSpongeChipset<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Create a new chip.
	pub fn new(initial_state: [AssignedCell<F, F>; WIDTH], default: AssignedCell<F, F>) -> Self {
		Self { state: initial_state, inputs: Vec::new(), default, _params: PhantomData }
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
		let mut inputs = self.inputs.clone();
		if self.inputs.is_empty() {
			inputs.push(self.default.clone());
		}

		let mut state = self.state.clone();
		for (i, chunk) in inputs.chunks(WIDTH).enumerate() {
			let mut curr_chunk = [(); WIDTH].map(|_| self.default.clone());
			for j in 0..chunk.len() {
				curr_chunk[j] = chunk[j].clone();
			}

			let absorb = AbsorbChip::new(state.clone(), curr_chunk.clone());
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
	/// Sponge chipset
	pub chipset: PoseidonSpongeChipset<F, WIDTH, P>,
	default: AssignedCell<F, F>,
}

impl<F: FieldExt, const WIDTH: usize, P> StatefulSpongeChipset<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Initialise the sponge
	pub fn init(common: &CommonConfig, mut layouter: impl Layouter<F>) -> Result<Self, Error> {
		let zero = layouter.assign_region(
			|| "load_initial_state",
			|region: Region<'_, F>| {
				let mut ctx = RegionCtx::new(region, 0);
				let zero_asgn = ctx.assign_from_constant(common.advice[0], F::ZERO)?;
				Ok(zero_asgn)
			},
		)?;
		let zero_state = [(); WIDTH].map(|_| zero.clone());
		let pos = PoseidonSpongeChipset::new(zero_state, zero.clone());
		Ok(Self { chipset: pos, default: zero.clone() })
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
		self.chipset = PoseidonSpongeChipset::new(res, self.default.clone());
		Ok(ret_value)
	}
}

#[cfg(test)]
mod test {
	use super::{AbsorbChip, PoseidonSpongeChipset, PoseidonSpongeConfig, StatefulSpongeChipset};
	use crate::{
		poseidon::{
			native::sponge::PoseidonSponge, FullRoundChip, PartialRoundChip, PoseidonConfig,
		},
		Chip, Chipset, CommonConfig, RegionCtx, ADVICE,
	};

	use crate::params::{hex_to_field, poseidon_bn254_5x5::Params};

	use halo2::{
		circuit::{Layouter, Region, SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::{bn256::Fr, ff::PrimeField},
		plonk::{Circuit, ConstraintSystem, Error},
	};
	use itertools::Itertools;

	const WIDTH: usize = 5;

	type TestPoseidonSponge = PoseidonSponge<Fr, WIDTH, Params>;
	type TestPoseidonSpongeChipset = PoseidonSpongeChipset<Fr, WIDTH, Params>;
	type FrChip = FullRoundChip<Fr, WIDTH, Params>;
	type PrChip = PartialRoundChip<Fr, WIDTH, Params>;

	#[derive(Clone)]
	struct PoseidonTesterConfig {
		common: CommonConfig,
		sponge: PoseidonSpongeConfig,
	}

	struct PoseidonTester {
		inputs: Vec<Value<Fr>>,
	}

	impl PoseidonTester {
		fn new(inputs: Vec<Fr>) -> Self {
			Self { inputs: inputs.iter().map(|&x| Value::known(x)).collect() }
		}
	}

	impl Circuit<Fr> for PoseidonTester {
		type Config = PoseidonTesterConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { inputs: vec![Value::unknown(); self.inputs.len()] }
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
			let common = CommonConfig::new(meta);
			let absorb_selector = AbsorbChip::<_, WIDTH>::configure(&common, meta);
			let pr_selector = PrChip::configure(&common, meta);
			let fr_selector = FrChip::configure(&common, meta);
			let poseidon = PoseidonConfig::new(fr_selector, pr_selector);
			let sponge = PoseidonSpongeConfig::new(poseidon, absorb_selector);

			Self::Config { common, sponge }
		}

		fn synthesize(
			&self, config: Self::Config, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let (inputs, zero) = layouter.assign_region(
				|| "load_inputs",
				|region: Region<'_, Fr>| {
					let mut ctx = RegionCtx::new(region, 0);

					let mut advice_i = 0;
					let mut assigned_inputs = Vec::new();
					for inp in &self.inputs {
						let assn_inp = ctx.assign_advice(config.common.advice[advice_i], *inp)?;
						assigned_inputs.push(assn_inp);

						advice_i += 1;
						if advice_i % ADVICE == 0 {
							advice_i = 0;
							ctx.next();
						}
					}

					let zero =
						ctx.assign_from_constant(config.common.advice[advice_i], Fr::zero())?;
					Ok((assigned_inputs, zero))
				},
			)?;

			let zero_state = [(); WIDTH].map(|_| zero.clone());
			let mut poseidon_sponge = TestPoseidonSpongeChipset::new(zero_state, zero.clone());
			poseidon_sponge.update(&inputs);
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
		let inputs: Vec<Fr> = [
			"0x0000000000000000000000000000000000000000000000000000000000000000",
			"0x0000000000000000000000000000000000000000000000000000000000000001",
			"0x0000000000000000000000000000000000000000000000000000000000000002",
			"0x0000000000000000000000000000000000000000000000000000000000000003",
			"0x0000000000000000000000000000000000000000000000000000000000000004",
			"0x0000000000000000000000000000000000000000000000000000000000000005",
			"0x0000000000000000000000000000000000000000000000000000000000000006",
			"0x0000000000000000000000000000000000000000000000000000000000000007",
			"0x0000000000000000000000000000000000000000000000000000000000000008",
			"0x0000000000000000000000000000000000000000000000000000000000000009",
		]
		.iter()
		.map(|n| hex_to_field(n))
		.collect();

		let mut sponge = TestPoseidonSponge::new();
		sponge.update(&inputs);
		let native_result = sponge.squeeze();
		let poseidon_sponge = PoseidonTester::new(inputs);

		let k = 12;
		let prover = MockProver::run(k, &poseidon_sponge, vec![vec![native_result]]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_match_native_sponge_empty() {
		// Testing circuit and native sponge equality.
		let inputs: Vec<Fr> = vec![];

		let mut sponge = TestPoseidonSponge::new();
		sponge.update(&inputs);
		let native_result = sponge.squeeze();
		let poseidon_sponge = PoseidonTester::new(inputs);

		let k = 12;
		let prover = MockProver::run(k, &poseidon_sponge, vec![vec![native_result]]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	struct PoseidonStatefulSpongeTester {
		inputs1: Vec<Value<Fr>>,
		inputs2: Vec<Value<Fr>>,
		inputs3: Vec<Value<Fr>>,
	}

	impl PoseidonStatefulSpongeTester {
		fn new(inputs1: Vec<Fr>, inputs2: Vec<Fr>, inputs3: Vec<Fr>) -> Self {
			Self {
				inputs1: inputs1.iter().map(|&x| Value::known(x)).collect_vec(),
				inputs2: inputs2.iter().map(|&x| Value::known(x)).collect_vec(),
				inputs3: inputs3.iter().map(|&x| Value::known(x)).collect_vec(),
			}
		}
	}

	impl Circuit<Fr> for PoseidonStatefulSpongeTester {
		type Config = PoseidonTesterConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self {
				inputs1: vec![Value::unknown(); self.inputs1.len()],
				inputs2: vec![Value::unknown(); self.inputs2.len()],
				inputs3: vec![Value::unknown(); self.inputs3.len()],
			}
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
			let common = CommonConfig::new(meta);
			let absorb_selector = AbsorbChip::<_, WIDTH>::configure(&common, meta);
			let pr_selector = PrChip::configure(&common, meta);
			let fr_selector = FrChip::configure(&common, meta);
			let poseidon = PoseidonConfig::new(fr_selector, pr_selector);
			let sponge = PoseidonSpongeConfig::new(poseidon, absorb_selector);

			Self::Config { common, sponge }
		}

		fn synthesize(
			&self, config: Self::Config, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let (inputs1, inputs2, inputs3) = layouter.assign_region(
				|| "load_inputs",
				|region: Region<'_, Fr>| {
					let mut ctx = RegionCtx::new(region, 0);

					let mut advice_i = 0;

					let mut assigned_inputs1 = Vec::new();
					for inp in &self.inputs1 {
						let assn_inp = ctx.assign_advice(config.common.advice[advice_i], *inp)?;
						assigned_inputs1.push(assn_inp);

						advice_i += 1;
						if advice_i % ADVICE == 0 {
							advice_i = 0;
							ctx.next();
						}
					}

					let mut assigned_inputs2 = Vec::new();
					for inp in &self.inputs2 {
						let assn_inp = ctx.assign_advice(config.common.advice[advice_i], *inp)?;
						assigned_inputs2.push(assn_inp);

						advice_i += 1;
						if advice_i % ADVICE == 0 {
							advice_i = 0;
							ctx.next();
						}
					}

					let mut assigned_inputs3 = Vec::new();
					for inp in &self.inputs3 {
						let assn_inp = ctx.assign_advice(config.common.advice[advice_i], *inp)?;
						assigned_inputs3.push(assn_inp);

						advice_i += 1;
						if advice_i % ADVICE == 0 {
							advice_i = 0;
							ctx.next();
						}
					}

					Ok((assigned_inputs1, assigned_inputs2, assigned_inputs3))
				},
			)?;

			let mut stateful_sponge = StatefulSpongeChipset::<_, WIDTH, Params>::init(
				&config.common,
				layouter.namespace(|| "init"),
			)?;
			stateful_sponge.update(&inputs1);
			let res1 = stateful_sponge.squeeze(
				&config.common,
				&config.sponge,
				layouter.namespace(|| "round1"),
			)?;
			stateful_sponge.update(&inputs2);
			let res2 = stateful_sponge.squeeze(
				&config.common,
				&config.sponge,
				layouter.namespace(|| "round2"),
			)?;
			stateful_sponge.update(&inputs3);
			let res3 = stateful_sponge.squeeze(
				&config.common,
				&config.sponge,
				layouter.namespace(|| "round3"),
			)?;

			layouter.constrain_instance(res1.cell(), config.common.instance, 0)?;
			layouter.constrain_instance(res2.cell(), config.common.instance, 1)?;
			layouter.constrain_instance(res3.cell(), config.common.instance, 2)?;
			Ok(())
		}
	}

	#[test]
	fn should_match_native_stateful_sponge() {
		// Testing circuit and native sponge equality.
		let inputs1: Vec<Fr> = vec![
			Fr::from_u128(1),
			Fr::from_u128(2),
			Fr::from_u128(3),
			Fr::from_u128(1),
			Fr::from_u128(2),
			Fr::from_u128(3),
			Fr::from_u128(1),
			Fr::from_u128(2),
			Fr::from_u128(3),
			Fr::from_u128(1),
			Fr::from_u128(2),
			Fr::from_u128(3),
		];
		let inputs2: Vec<Fr> = vec![];
		let inputs3: Vec<Fr> = vec![Fr::from_u128(1), Fr::from_u128(2), Fr::from_u128(3)];

		let mut sponge = TestPoseidonSponge::new();
		sponge.update(&inputs1);
		let res1 = sponge.squeeze();
		sponge.update(&inputs2);
		let res2 = sponge.squeeze();
		sponge.update(&inputs3);
		let res3 = sponge.squeeze();

		let poseidon_sponge = PoseidonStatefulSpongeTester::new(inputs1, inputs2, inputs3);

		let k = 12;
		let prover = MockProver::run(k, &poseidon_sponge, vec![vec![res1, res2, res3]]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}
}
