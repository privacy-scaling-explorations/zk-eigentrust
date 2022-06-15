use std::marker::PhantomData;

use super::RoundParams;
use ecc::maingate::RegionCtx;
use halo2wrong::halo2::{arithmetic::FieldExt, plonk::Error};
use maingate::{AssignedValue, MainGate, MainGateConfig, MainGateInstructions};

pub struct PoseidonChip<F: FieldExt, const WIDTH: usize, P: RoundParams<F, WIDTH>>(
	MainGate<F>,
	PhantomData<P>,
);

impl<F: FieldExt, const WIDTH: usize, P: RoundParams<F, WIDTH>> PoseidonChip<F, WIDTH, P> {
	pub fn new(main_gate_config: MainGateConfig) -> Self {
		let main_gate = MainGate::new(main_gate_config);
		Self(main_gate, PhantomData)
	}

	pub fn main_gate(&self) -> &MainGate<F> {
		&self.0
	}
}

impl<F: FieldExt, const WIDTH: usize, P: RoundParams<F, WIDTH>> PoseidonChip<F, WIDTH, P> {
	fn apply_round_constants(
		&self,
		ctx: &mut RegionCtx<'_, '_, F>,
		state: &[AssignedValue<F>; WIDTH],
		round_consts: &[F; WIDTH],
	) -> Result<[AssignedValue<F>; WIDTH], Error> {
		let main_gate = self.main_gate();

		let mut new_state = state.clone();
		for i in 0..WIDTH {
			let sum = main_gate.add_constant(ctx, &state[i], round_consts[i])?;
			new_state[i] = sum;
		}

		Ok(new_state)
	}

	fn apply_mds(
		&self,
		ctx: &mut RegionCtx<'_, '_, F>,
		state: &[AssignedValue<F>; WIDTH],
		mds: &[[AssignedValue<F>; WIDTH]; WIDTH],
		zero_state: &[AssignedValue<F>; WIDTH],
	) -> Result<[AssignedValue<F>; WIDTH], Error> {
		let main_gate = self.main_gate();
		let mut new_state = zero_state.clone();
		// Compute mds matrix
		for i in 0..WIDTH {
			for j in 0..WIDTH {
				let m_product = main_gate.mul(ctx, &state[j], &mds[i][j])?;
				new_state[i] = main_gate.add(ctx, &new_state[i], &m_product)?;
			}
		}
		Ok(new_state)
	}

	pub fn permute(
		&self,
		ctx: &mut RegionCtx<'_, '_, F>,
		mut state: [AssignedValue<F>; WIDTH],
	) -> Result<[AssignedValue<F>; WIDTH], Error> {
		let main_gate = self.main_gate();

		let full_rounds = P::full_rounds();
		let half_full_rounds = full_rounds / 2;
		let partial_rounds = P::partial_rounds();
		let mds = P::mds();
		let round_constants = P::round_constants();
		let total_count = P::round_constants_count();

		let first_round_end = half_full_rounds * WIDTH;
		let first_round_constants = &round_constants[0..first_round_end];

		let second_round_end = first_round_end + partial_rounds * WIDTH;
		let second_round_constants = &round_constants[first_round_end..second_round_end];

		let third_round_constants = &round_constants[second_round_end..total_count];

		let mds_assigned =
			mds.try_map(|vec| vec.try_map(|val| main_gate.assign_constant(ctx, val)))?;
		let zero_state = [(); WIDTH].try_map(|_| main_gate.assign_constant(ctx, F::zero()))?;

		for round in 0..half_full_rounds {
			let round_consts = P::load_round_constants(round, first_round_constants);
			state = self.apply_round_constants(ctx, &state, &round_consts)?;
			for i in 0..WIDTH {
				state[i] = P::sbox_asgn(&main_gate, ctx, &state[i])?;
			}
			state = self.apply_mds(ctx, &state, &mds_assigned, &zero_state)?;
		}

		for round in 0..partial_rounds {
			let round_consts = P::load_round_constants(round, second_round_constants);
			state = self.apply_round_constants(ctx, &state, &round_consts)?;
			state[0] = P::sbox_asgn(&main_gate, ctx, &state[0])?;
			state = self.apply_mds(ctx, &state, &mds_assigned, &zero_state)?;
		}

		for round in 0..half_full_rounds {
			let round_consts = P::load_round_constants(round, third_round_constants);
			state = self.apply_round_constants(ctx, &state, &round_consts)?;
			for i in 0..WIDTH {
				state[i] = P::sbox_asgn(&main_gate, ctx, &state[i])?;
			}
			state = self.apply_mds(ctx, &state, &mds_assigned, &zero_state)?;
		}

		Ok(state)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::poseidon::params::{hex_to_field, Params5x5Bn254};
	use halo2wrong::{
		curves::bn256::Fr,
		halo2::{
			circuit::{Layouter, SimpleFloorPlanner},
			dev::MockProver,
			plonk::{Circuit, ConstraintSystem, Error},
		},
	};
	use maingate::UnassignedValue;

	type TestPoseidonChip = PoseidonChip<Fr, 5, Params5x5Bn254>;

	#[derive(Clone)]
	struct PoseidonTesterConfig {
		main_config: MainGateConfig,
	}

	struct PoseidonTester {
		inputs: [Option<Fr>; 5],
	}

	impl PoseidonTester {
		fn new(inputs: [Option<Fr>; 5]) -> Self {
			Self { inputs }
		}
	}

	impl Circuit<Fr> for PoseidonTester {
		type Config = PoseidonTesterConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { inputs: [None; 5] }
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
			let main_config = MainGate::<Fr>::configure(meta);

			Self::Config { main_config }
		}

		fn synthesize(
			&self,
			config: Self::Config,
			mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let maingate = MainGate::new(config.main_config.clone());

			let out_state = layouter.assign_region(
				|| "acc",
				|mut region| {
					let position = &mut 0;
					let ctx = &mut RegionCtx::new(&mut region, position);

					let unassigned = self.inputs.map(|val| UnassignedValue::from(val));
					let assigned_inp =
						unassigned.try_map(|val| maingate.assign_value(ctx, &val))?;

					let poseidon = TestPoseidonChip::new(config.main_config.clone());
					let res = poseidon.permute(ctx, assigned_inp)?;

					Ok(res)
				},
			)?;

			for i in 0..5 {
				maingate.expose_public(
					layouter.namespace(|| "poseidon output"),
					out_state[i],
					i,
				)?;
			}

			Ok(())
		}
	}

	#[test]
	fn test_poseidon_wrong_x5_5() {
		let inputs: [Option<Fr>; 5] = [
			"0x0000000000000000000000000000000000000000000000000000000000000000",
			"0x0000000000000000000000000000000000000000000000000000000000000001",
			"0x0000000000000000000000000000000000000000000000000000000000000002",
			"0x0000000000000000000000000000000000000000000000000000000000000003",
			"0x0000000000000000000000000000000000000000000000000000000000000004",
		]
		.map(|n| Some(hex_to_field(n)));

		let outputs: [Fr; 5] = [
			"0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465",
			"0x1148aaef609aa338b27dafd89bb98862d8bb2b429aceac47d86206154ffe053d",
			"0x24febb87fed7462e23f6665ff9a0111f4044c38ee1672c1ac6b0637d34f24907",
			"0x0eb08f6d809668a981c186beaf6110060707059576406b248e5d9cf6e78b3d3e",
			"0x07748bc6877c9b82c8b98666ee9d0626ec7f5be4205f79ee8528ef1c4a376fc7",
		]
		.map(|n| hex_to_field(n));

		let poseidon_tester = PoseidonTester::new(inputs);

		let k = 12;
		let prover = MockProver::run(k, &poseidon_tester, vec![outputs.to_vec()]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}
}
