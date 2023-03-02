use halo2::{
	dev::MockProver,
	halo2curves::{
		bn256::{Bn256, Fq, Fr, G1Affine},
		group::ff::PrimeField,
	},
	plonk::{create_proof, keygen_pk, keygen_vk, Circuit, ProvingKey, VerifyingKey},
	poly::{
		commitment::{Params, ParamsProver},
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
use snark_verifier::{
	loader::evm::{self, Address, EvmLoader, ExecutorBuilder},
	pcs::kzg::{Gwc19, KzgAs},
	system::halo2::{compile, transcript::evm::EvmTranscript, Config},
	verifier::{self, SnarkVerifier},
};
use std::rc::Rc;

/// Halo2 loader
pub mod loader;
/// Poseidon transcript
pub mod transcript;

type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;

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

/// Generate SRS
pub fn gen_srs(k: u32) -> ParamsKZG<Bn256> {
	ParamsKZG::<Bn256>::setup(k, OsRng)
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

/// Generate solidity verifier
pub fn gen_evm_verifier(
	params: &ParamsKZG<Bn256>, vk: &VerifyingKey<G1Affine>, num_instance: Vec<usize>,
) -> Vec<u8> {
	let code = gen_evm_verifier_code(params, vk, num_instance);
	evm::compile_yul(&code)
}

/// Generate solidity verifier
pub fn gen_evm_verifier_code(
	params: &ParamsKZG<Bn256>, vk: &VerifyingKey<G1Affine>, num_instance: Vec<usize>,
) -> String {
	let protocol = compile(
		params,
		vk,
		Config::kzg().with_num_instance(num_instance.clone()),
	);

	let loader = EvmLoader::new::<Fq, Fr>();
	let protocol = protocol.loaded(&loader);
	let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

	let instances = transcript.load_instances(num_instance);
	let vk = (params.get_g()[0], params.g2(), params.s_g2()).into();

	let proof = PlonkVerifier::read_proof(&vk, &protocol, &instances, &mut transcript).unwrap();
	PlonkVerifier::verify(&vk, &protocol, &instances, &proof).unwrap();

	loader.yul_code()
}

/// Verify proof inside the smart contract
pub fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
	let calldata = encode_calldata(&instances, &proof);
	let mut evm = ExecutorBuilder::default().with_gas_limit(u64::MAX.into()).build();

	let caller = Address::from_low_u64_be(0xfe);
	let deployment_result = evm.deploy(caller, deployment_code.into(), 0.into());
	dbg!(deployment_result.exit_reason);

	let verifier_address = deployment_result.address.unwrap();
	let result = evm.call_raw(caller, verifier_address, calldata.into(), 0.into());

	dbg!(result.gas_used);
	dbg!(result.reverted);
	dbg!(result.exit_reason);

	let success = !result.reverted;
	assert!(success);
}

#[cfg(test)]
mod test {
	use std::usize;

	use super::{gen_evm_verifier, gen_pk, gen_proof, gen_srs};
	use crate::{
		utils::{
			generate_params, prove_and_verify, write_bytes_data, write_json_data, write_yul_data,
		},
		verifier::{evm_verify, gen_evm_verifier_code},
		Proof, ProofRaw, RegionCtx,
	};
	use halo2::{
		circuit::{Layouter, Region, SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::{
			bn256::{Bn256, Fr},
			FieldExt,
		},
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

				let mut sum = Expression::Constant(F::zero());
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

						let mut sum = Value::known(F::zero());
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
		let k = 9;

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

		let k = 9;
		let params = generate_params(k);

		let pub_ins = vec![sum; VERTICAL_SIZE];
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[&pub_ins], rng).unwrap();
		assert!(res);
	}

	#[test]
	fn verify_dummy_pi_evm() {
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

		let k = 9;
		let params = gen_srs(k);
		let pk = gen_pk(&params, &circuit);
		let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![VERTICAL_SIZE]);
		dbg!(deployment_code.len());

		let pub_ins = vec![sum; VERTICAL_SIZE];
		let proof = gen_proof(&params, &pk, circuit.clone(), vec![pub_ins.clone()]);
		evm_verify(deployment_code, vec![pub_ins.clone()], proof.clone());

		let k = 14;
		let params = gen_srs(k);
		let pk = gen_pk(&params, &circuit);
		let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![VERTICAL_SIZE]);
		let contract_code = gen_evm_verifier_code(&params, pk.get_vk(), vec![VERTICAL_SIZE]);
		write_bytes_data(deployment_code, "test_verifier").unwrap();
		write_yul_data(contract_code, "test_verifier").unwrap();

		let proof = Proof { pub_ins, proof };
		let proof_raw: ProofRaw = proof.into();

		write_json_data(proof_raw, "test_proof").unwrap();
	}
}
