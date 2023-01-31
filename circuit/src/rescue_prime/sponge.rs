use super::copy_state;
use crate::{
	params::RoundParams, rescue_prime::RescuePrimeChip, Chip, Chipset, CommonConfig, RegionCtx,
};
use halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region},
	plonk::{ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};
use std::marker::PhantomData;

/// A chip for absorbing the previous RescuePrime state
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
				let rescue_prime_exp = v_cells.query_advice(common.advice[i], Rotation::cur());
				let sponge_exp = v_cells.query_advice(common.advice[i], Rotation::next());
				let next_sponge_exp = v_cells.query_advice(common.advice[i], Rotation(2));
				let diff = next_sponge_exp - (sponge_exp + rescue_prime_exp);
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
			|region: Region<'_, F>| {
				let mut ctx = RegionCtx::new(region, 0);
				ctx.enable(selector.clone())?;

				// Load previous RescuePrime state
				let loaded_state = copy_state(&mut ctx, common, &self.prev_state)?;
				ctx.next();

				// Load next chunk
				let loaded_chunk = copy_state(&mut ctx, common, &self.state)?;
				ctx.next();

				// Calculate the next state to permute
				let columns = common.advice[0..WIDTH].try_into().unwrap();
				let collection = loaded_chunk.zip(loaded_state).zip(columns);
				let next_state = collection.try_map(|((chunk_state, pos_state), column)| {
					let sum = chunk_state.value().and_then(|&s| {
						let pos_state_val = pos_state.value();
						pos_state_val.map(|&ps| s + ps)
					});
					ctx.assign_advice(column, sum)
				})?;

				Ok(next_state)
			},
		)
	}
}

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
					let zero_asgn = ctx.assign_from_constant(common.advice[i], F::zero())?;
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
