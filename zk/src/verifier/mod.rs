use halo2::{
	dev::MockProver,
	halo2curves::{
		bn256::{Bn256, Fr, G1Affine},
		group::ff::PrimeField,
	},
	plonk::{create_proof, keygen_pk, keygen_vk, Circuit, ProvingKey},
	poly::{
		commitment::Params,
		kzg::{
			commitment::{KZGCommitmentScheme, ParamsKZG},
			multiopen::ProverGWC,
		},
	},
	transcript::TranscriptWriterBuffer,
};
use itertools::Itertools;
use rand::rngs::OsRng;
pub use snark_verifier::loader::evm::compile_yul;
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;

/// PLONK proof aggregator
pub mod aggregator;
/// Halo2 loader
pub mod loader;
/// Poseidon transcript
pub mod transcript;

/// Encode instances and proof into calldata.
pub fn encode_calldata<F>(instances: &[Vec<F>], proof: &[u8]) -> Vec<u8>
where
	F: PrimeField<Repr = [u8; 32]>,
{
	let mut calldata = Vec::new();
	for inst_row in instances {
		for value in inst_row {
			let mut bytes = value.to_repr();
			bytes.reverse();
			calldata.extend(bytes);
		}
	}
	calldata.extend(proof);

	calldata
}

/// Generate Public Key
pub fn gen_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine> {
	let vk = keygen_vk(params, circuit).unwrap();
	keygen_pk(params, vk, circuit).unwrap()
}

/// Generate proof
pub fn gen_proof<C: Circuit<Fr>>(
	params: &ParamsKZG<Bn256>, pk: &ProvingKey<G1Affine>, circuit: C, instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
	MockProver::run(params.k(), &circuit, instances.clone()).unwrap().assert_satisfied();

	let instances = instances.iter().map(|instances| instances.as_slice()).collect_vec();
	let proof = {
		let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());
		create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, EvmTranscript<_, _, _, _>, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
		transcript.finalize()
	};

	proof
}

#[cfg(test)]
mod test {
	use std::usize;

	use crate::{
		utils::{generate_params, prove_and_verify},
		FieldExt, RegionCtx,
	};
	use halo2::{
		circuit::{Layouter, Region, SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::bn256::{Bn256, Fr},
		plonk::{
			Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
		},
		poly::Rotation,
	};

	const NUM_ADVICE: usize = 2;
	const NUM_FIXED: usize = 2;
	const VERTICAL_SIZE: usize = 1;

	#[derive(Clone)]
	struct TestConfigPi {
		advice: [Column<Advice>; NUM_ADVICE],
		fixed: [Column<Fixed>; NUM_FIXED],
		pi: Column<Instance>,
		selector: Selector,
	}

	#[derive(Clone)]
	struct TestCircuitPi<F: FieldExt, const S: usize> {
		advice: [Value<F>; NUM_ADVICE],
		fixed: [F; NUM_FIXED],
	}

	impl<F: FieldExt, const S: usize> TestCircuitPi<F, S> {
		fn new(advice: [F; NUM_ADVICE], fixed: [F; NUM_FIXED]) -> Self {
			Self { advice: advice.map(|x| Value::known(x)), fixed }
		}
	}

	impl<F: FieldExt, const S: usize> Circuit<F> for TestCircuitPi<F, S> {
		type Config = TestConfigPi;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { advice: [(); NUM_ADVICE].map(|_| Value::unknown()), fixed: self.fixed.clone() }
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestConfigPi {
			let advice = [(); NUM_ADVICE].map(|_| meta.advice_column());
			let fixed = [(); NUM_FIXED].map(|_| meta.fixed_column());
			let pi = meta.instance_column();
			let s = meta.selector();

			advice.map(|c| meta.enable_equality(c));
			fixed.map(|c| meta.enable_equality(c));
			meta.enable_equality(pi);

			meta.create_gate("add", |v_cells| {
				let s_exp = v_cells.query_selector(s);
				let advice_set_exp = advice.map(|c| v_cells.query_advice(c, Rotation::cur()));
				let fixed_set_exp = fixed.map(|c| v_cells.query_fixed(c, Rotation::cur()));

				let mut sum = Expression::Constant(F::ZERO);
				for i in 0..advice_set_exp.len() {
					sum = sum + advice_set_exp[i].clone();
				}
				for i in 0..fixed_set_exp.len() {
					sum = sum + fixed_set_exp[i].clone();
				}

				let c_exp = v_cells.query_advice(advice[0], Rotation::next());

				let res = c_exp - sum;

				vec![s_exp * res]
			});

			TestConfigPi { advice, fixed, pi, selector: s }
		}

		fn synthesize(
			&self, config: TestConfigPi, mut layouter: impl Layouter<F>,
		) -> Result<(), Error> {
			for s in 0..S {
				let res = layouter.assign_region(
					|| "add",
					|region: Region<'_, F>| {
						let mut ctx = RegionCtx::new(region, 0);
						ctx.enable(config.selector)?;

						for i in 0..self.advice.len() {
							ctx.assign_advice(config.advice[i], self.advice[i])?;
						}
						for i in 0..self.fixed.len() {
							ctx.assign_fixed(config.fixed[i], self.fixed[i])?;
						}

						let mut sum = Value::known(F::ZERO);
						for i in 0..self.advice.len() {
							sum = sum + self.advice[i];
						}
						for i in 0..self.fixed.len() {
							sum = sum + Value::known(self.fixed[i]);
						}

						ctx.next();

						let c_cell = ctx.assign_advice(config.advice[0], sum)?;
						Ok(c_cell)
					},
				)?;

				layouter.constrain_instance(res.cell(), config.pi, s)?;
			}

			Ok(())
		}
	}

	#[test]
	fn verify_dummy_pi_dev() {
		let advice = [Fr::one(); NUM_ADVICE];
		let fixed = [Fr::one(); NUM_FIXED];
		let mut sum = Fr::zero();
		for i in 0..advice.len() {
			sum += advice[i];
		}
		for i in 0..fixed.len() {
			sum += fixed[i];
		}

		let circuit = TestCircuitPi::<_, VERTICAL_SIZE>::new(advice, fixed);
		let k = 4;

		let pub_ins = vec![sum; VERTICAL_SIZE];
		let prover = MockProver::run(k, &circuit, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn verify_dummy_pi_prod() {
		let rng = &mut rand::thread_rng();
		let advice = [Fr::one(); NUM_ADVICE];
		let fixed = [Fr::one(); NUM_FIXED];
		let mut sum = Fr::zero();
		for i in 0..advice.len() {
			sum += advice[i];
		}
		for i in 0..fixed.len() {
			sum += fixed[i];
		}
		let circuit = TestCircuitPi::<_, VERTICAL_SIZE>::new(advice, fixed);

		let k = 4;
		let params = generate_params(k);

		let pub_ins = vec![sum; VERTICAL_SIZE];
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[&pub_ins], rng).unwrap();
		assert!(res);
	}
}
