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
	use halo2::halo2curves::{bn256::Fr, FieldExt};
	use rand::thread_rng;
	use snark_verifier::loader::evm::{encode_calldata, Address, ExecutorBuilder};

	use crate::{
		circuit::{native, EigenTrust, PoseidonNativeHasher, PoseidonNativeSponge},
		eddsa::native::{sign, SecretKey, Signature},
	};

	use super::{gen_evm_verifier, gen_pk, gen_proof, gen_srs};

	fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
		let calldata = encode_calldata(&instances, &proof);
		let success = {
			let mut evm = ExecutorBuilder::default().with_gas_limit(u64::MAX.into()).build();

			let caller = Address::from_low_u64_be(0xfe);
			let deployment_result = evm.deploy(caller, deployment_code.into(), 0.into());
			dbg!(deployment_result.exit_reason);
			let verifier_address = deployment_result.address.unwrap();
			let result = evm.call_raw(caller, verifier_address, calldata.into(), 0.into());

			dbg!(result.gas_used);

			!result.reverted
		};
		assert!(success);
	}

	pub const NUM_ITER: usize = 10;
	pub const NUM_NEIGHBOURS: usize = 5;
	pub const INITIAL_SCORE: u128 = 1000;
	pub const SCALE: u128 = 1000;

	#[test]
	#[ignore = "SmartContract size too big"]
	fn verify_eigen_trust_evm() {
		let s = vec![Fr::from_u128(INITIAL_SCORE); NUM_NEIGHBOURS];
		let ops: Vec<Vec<Fr>> = vec![
			vec![0, 200, 300, 500, 0],
			vec![100, 0, 100, 100, 700],
			vec![400, 100, 0, 200, 300],
			vec![100, 100, 700, 0, 100],
			vec![300, 100, 400, 200, 0],
		]
		.into_iter()
		.map(|arr| arr.into_iter().map(|x| Fr::from_u128(x)).collect())
		.collect();
		let res = native::<Fr, NUM_NEIGHBOURS, NUM_ITER, SCALE>(s, ops.clone());

		let rng = &mut thread_rng();
		let secret_keys = [(); NUM_NEIGHBOURS].map(|_| SecretKey::random(rng));
		let pub_keys = secret_keys.clone().map(|x| x.public());

		let pk_x = pub_keys.clone().map(|pk| pk.0.x);
		let pk_y = pub_keys.clone().map(|pk| pk.0.y);
		let mut sponge = PoseidonNativeSponge::new();
		sponge.update(&pk_x);
		sponge.update(&pk_y);
		let keys_message_hash = sponge.squeeze();

		let messages: Vec<Fr> = ops
			.iter()
			.map(|scores| {
				let mut sponge = PoseidonNativeSponge::new();
				sponge.update(&scores);
				let scores_message_hash = sponge.squeeze();

				let m_inputs =
					[keys_message_hash, scores_message_hash, Fr::zero(), Fr::zero(), Fr::zero()];
				let poseidon = PoseidonNativeHasher::new(m_inputs);
				let res = poseidon.permute()[0];
				res
			})
			.collect();

		let signatures: Vec<Signature> = secret_keys
			.into_iter()
			.zip(pub_keys.clone())
			.zip(messages.clone())
			.map(|((sk, pk), msg)| sign(&sk, &pk, msg))
			.collect();

		let et = EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::new(
			pub_keys.to_vec(),
			signatures,
			ops,
			messages,
		);

		let k = 14;
		let params = gen_srs(k);
		let pk = gen_pk(&params, &et);
		let deployment_code = gen_evm_verifier(&params, pk.get_vk(), vec![NUM_NEIGHBOURS]);
		dbg!(deployment_code.len());

		let proof = gen_proof(&params, &pk, et.clone(), vec![res.clone()]);
		evm_verify(deployment_code, vec![res], proof);
	}
}
