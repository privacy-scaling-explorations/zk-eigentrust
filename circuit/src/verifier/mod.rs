use halo2::{
	dev::MockProver,
	halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
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
use snark_verifier::{
	loader::evm::{self, EvmLoader},
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

fn gen_srs(k: u32) -> ParamsKZG<Bn256> {
	ParamsKZG::<Bn256>::setup(k, OsRng)
}

fn gen_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine> {
	let vk = keygen_vk(params, circuit).unwrap();
	keygen_pk(params, vk, circuit).unwrap()
}

fn gen_proof<C: Circuit<Fr>>(
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

fn gen_evm_verifier(
	params: &ParamsKZG<Bn256>, vk: &VerifyingKey<G1Affine>, num_instance: Vec<usize>,
) -> Vec<u8> {
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

	evm::compile_yul(&loader.yul_code())
}

#[cfg(test)]
mod test {
	use crate::RegionCtx;

	use super::{gen_evm_verifier, gen_pk, gen_proof, gen_srs};
	use halo2::{
		circuit::{Chip, Layouter, Region, SimpleFloorPlanner, Value},
		halo2curves::{bn256::Fr, FieldExt},
		plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
		poly::Rotation,
	};
	use rand::thread_rng;
	use snark_verifier::loader::evm::{encode_calldata, Address, ExecutorBuilder};

	#[derive(Clone)]
	struct TestConfig {
		a: Column<Advice>,
		b: Column<Advice>,
		selector: Selector,
	}

	#[derive(Clone)]
	struct TestCircuit<F: FieldExt> {
		a: Value<F>,
		b: Value<F>,
	}

	impl<F: FieldExt> TestCircuit<F> {
		fn new(a: F, b: F) -> Self {
			Self { a: Value::known(a), b: Value::known(b) }
		}
	}

	impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { a: Value::unknown(), b: Value::unknown() }
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
			let a = meta.advice_column();
			let b = meta.advice_column();
			let s = meta.selector();

			meta.create_gate("add", |v_cells| {
				let s_exp = v_cells.query_selector(s);
				let a_exp = v_cells.query_advice(a, Rotation::cur());
				let b_exp = v_cells.query_advice(b, Rotation::cur());
				let c_exp = v_cells.query_advice(a, Rotation::next());

				let c_exp = c_exp - (a_exp + b_exp);

				vec![s_exp * c_exp]
			});

			TestConfig { a, b, selector: s }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<F>,
		) -> Result<(), Error> {
			layouter.assign_region(
				|| "add",
				|region: Region<'_, F>| {
					let mut ctx = RegionCtx::new(region, 0);
					ctx.enable(config.selector)?;

					ctx.assign_advice(config.a, self.a)?;
					ctx.assign_advice(config.b, self.b)?;

					ctx.next();

					let c = self.a + self.b;
					ctx.assign_advice(config.a, c)?;

					Ok(())
				},
			)
		}
	}

	fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
		let calldata = encode_calldata(&instances, &proof);
		let success = {
			let mut evm = ExecutorBuilder::default().with_gas_limit(u64::MAX.into()).build();

			let caller = Address::from_low_u64_be(0xfe);
			let deployment_result = evm.deploy(caller, deployment_code.into(), 0.into());
			dbg!(deployment_result.exit_reason);
			let verifier_address = deployment_result.address.unwrap();
			let result = evm.call_raw(caller, verifier_address, calldata.into(), 0.into());

			let reverted = result.reverted;
			dbg!(result.gas_used);
			dbg!(result);

			!reverted
		};
		assert!(success);
	}

	#[test]
	// #[ignore = "SmartContract size too big"]
	fn verify_eigen_trust_evm() {
		let a = Fr::one();
		let b = Fr::one();

		let circuit = TestCircuit::new(a, b);

		let k = 14;
		let params = gen_srs(k);
		let pk = gen_pk(&params, &circuit);
		let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![5]);
		dbg!(deployment_code.len());

		let proof = gen_proof(&params, &pk, circuit.clone(), vec![]);
		evm_verify(deployment_code, vec![], proof);
	}
}
