use crate::{
	gadgets::absorb::AbsorbChip, params::RoundParams, rescue_prime::RescuePrimeChip, Chip, Chipset,
	CommonConfig, FieldExt, RegionCtx, SpongeHasherChipset,
};
use halo2::{
	circuit::{AssignedCell, Layouter, Region},
	plonk::{Error, Selector},
};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
/// Selectors for RescuePrime sponge
pub struct RescuePrimeSpongeConfig {
	rescue_prime_selector: Selector,
	absorb_selector: Selector,
}

impl RescuePrimeSpongeConfig {
	/// Constructs a new config
	pub fn new(rescue_prime_selector: Selector, absorb_selector: Selector) -> Self {
		Self { rescue_prime_selector, absorb_selector }
	}
}

#[derive(Clone)]
/// Constructs a chip structure for the circuit.
pub struct RescuePrimeSpongeChipset<F: FieldExt, const WIDTH: usize, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Constructs a cell vector for the inputs.
	inputs: Vec<AssignedCell<F, F>>,
	/// Constructs a phantom data for the parameters.
	_params: PhantomData<P>,
}

impl<F: FieldExt, const WIDTH: usize, P> RescuePrimeSpongeChipset<F, WIDTH, P>
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

impl<F: FieldExt, const WIDTH: usize, P> Chipset<F> for RescuePrimeSpongeChipset<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	type Config = RescuePrimeSpongeConfig;
	type Output = AssignedCell<F, F>;

	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		assert!(!self.inputs.is_empty());

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

			let rescue_prime = RescuePrimeChip::<_, WIDTH, P>::new(inputs);
			state = rescue_prime.synthesize(
				common,
				&config.rescue_prime_selector,
				layouter.namespace(|| format!("rescue_prime_permute_{}", i)),
			)?;
		}

		Ok(state[0].clone())
	}
}

impl<F: FieldExt, const WIDTH: usize, P> SpongeHasherChipset<F>
	for RescuePrimeSpongeChipset<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	fn new() -> Self {
		Self::new()
	}

	fn update(&mut self, inputs: &[AssignedCell<F, F>]) {
		Self::update(self, inputs)
	}

	fn squeeze(
		self, common: &CommonConfig, config: &Self::Config, layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		Self::synthesize(self, common, config, layouter)
	}
}

#[cfg(test)]
mod test {
	use super::{AbsorbChip, RescuePrimeSpongeChipset, RescuePrimeSpongeConfig};
	use crate::{
		rescue_prime::{native::sponge::RescuePrimeSponge, RescuePrimeChip},
		Chip, Chipset, CommonConfig, RegionCtx,
	};

	use crate::params::{hex_to_field, rescue_prime_bn254_5x5::Params};

	use halo2::{
		circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::bn256::Fr,
		plonk::{Circuit, ConstraintSystem, Error},
	};

	type TestRescuePrimeSponge = RescuePrimeSponge<Fr, 5, Params>;
	type TestRescuePrimeSpongeChipset = RescuePrimeSpongeChipset<Fr, 5, Params>;

	#[derive(Clone)]
	struct RescuePrimeTesterConfig {
		common: CommonConfig,
		sponge: RescuePrimeSpongeConfig,
	}

	struct RescuePrimeTester {
		inputs1: [Value<Fr>; 5],
		inputs2: [Value<Fr>; 5],
	}

	impl RescuePrimeTester {
		fn new(inputs1: [Fr; 5], inputs2: [Fr; 5]) -> Self {
			Self {
				inputs1: inputs1.map(|item| Value::known(item)),
				inputs2: inputs2.map(|item| Value::known(item)),
			}
		}
	}

	impl Circuit<Fr> for RescuePrimeTester {
		type Config = RescuePrimeTesterConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { inputs1: [Value::unknown(); 5], inputs2: [Value::unknown(); 5] }
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
			let common = CommonConfig::new(meta);
			let absorb_selector = AbsorbChip::<_, 5>::configure(&common, meta);
			let rescue_prime_selector = RescuePrimeChip::<_, 5, Params>::configure(&common, meta);
			let sponge = RescuePrimeSpongeConfig::new(rescue_prime_selector, absorb_selector);
			Self::Config { common, sponge }
		}

		fn synthesize(
			&self, config: Self::Config, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
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

			let mut rescue_prime_sponge = TestRescuePrimeSpongeChipset::new();
			rescue_prime_sponge.update(&inputs1);
			rescue_prime_sponge.update(&inputs2);
			let result_state = rescue_prime_sponge.synthesize(
				&config.common,
				&config.sponge,
				layouter.namespace(|| "rescue_prime_sponge"),
			)?;

			layouter.constrain_instance(result_state.cell(), config.common.instance, 0)?;

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

		let mut sponge = TestRescuePrimeSponge::new();
		sponge.update(&inputs1);
		sponge.update(&inputs2);

		let native_result = sponge.squeeze();

		let rescue_prime_sponge = RescuePrimeTester::new(inputs1, inputs2);

		let k = 12;
		let prover = MockProver::run(k, &rescue_prime_sponge, vec![vec![native_result]]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}
}
