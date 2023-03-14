use halo2::{
	circuit::Value,
	halo2curves::bn256::{Bn256, Fr, G1Affine},
	plonk::VerifyingKey,
	poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use rand::thread_rng;
use snark_verifier::{
	pcs::{
		kzg::{Gwc19, KzgAccumulator, KzgAs},
		AccumulationSchemeProver,
	},
	system::halo2::{compile, Config},
	verifier::{
		plonk::{PlonkProtocol, PlonkSuccinctVerifier},
		SnarkVerifier,
	},
};

use crate::{
	integer::{native::Integer, rns::Bn256_4_68},
	params::poseidon_bn254_5x5::Params,
};

use super::{
	loader::{LScalar, NativeLoader},
	transcript::{PoseidonRead, PoseidonWrite},
};

type PSV = PlonkSuccinctVerifier<KzgAs<Bn256, Gwc19>>;

#[derive(Clone)]
/// Snark witness structure
pub struct SnarkWitness {
	protocol: PlonkProtocol<G1Affine>,
	instances: Vec<Vec<Value<Fr>>>,
	proof: Value<Vec<u8>>,
}

impl SnarkWitness {
	fn without_witnesses(&self) -> Self {
		SnarkWitness {
			protocol: self.protocol.clone(),
			instances: self
				.instances
				.iter()
				.map(|instances| vec![Value::unknown(); instances.len()])
				.collect(),
			proof: Value::unknown(),
		}
	}

	fn proof(&self) -> Value<&[u8]> {
		self.proof.as_ref().map(Vec::as_slice)
	}
}

struct Aggregator {
	instances: Vec<Fr>,
}

impl Aggregator {
	pub fn new(
		params: &ParamsKZG<Bn256>, vk: &VerifyingKey<G1Affine>, num_instance: Vec<usize>,
		proof: Vec<u8>, instances: Vec<LScalar<G1Affine, Bn256_4_68>>,
	) -> Self {
		let protocol = compile(
			params,
			vk,
			Config::kzg().with_num_instance(num_instance.clone()),
		);

		let loader = NativeLoader::default();
		let protocol = protocol.loaded(&loader);
		let mut transcript_read: PoseidonRead<_, G1Affine, Bn256_4_68, Params> =
			PoseidonRead::new(proof.as_slice(), loader);

		let svk = params.get_g()[0].into();

		let proof =
			PSV::read_proof(&svk, &protocol, &[instances.clone()], &mut transcript_read).unwrap();
		let accumulators = PSV::verify(&svk, &protocol, &[instances], &proof).unwrap();

		let mut transcript_write =
			PoseidonWrite::<Vec<u8>, G1Affine, Bn256_4_68, Params>::new(Vec::new());

		let rng = &mut thread_rng();
		// TODO: uncomment when TranscriptRead with NativeLoader from snark-verifier is
		// implemented

		// let accumulator = KzgAs::<Bn256, Gwc19>::create_proof(
		// 	&Default::default(),
		// 	&accumulators,
		// 	&mut transcript_write,
		// 	rng,
		// )
		// .unwrap();

		// let KzgAccumulator { lhs, rhs } = accumulator;
		// let instances = [lhs.x, lhs.y, rhs.x, rhs.y].map(|v|
		// Integer::from_w(v).limbs).concat();

		Self { instances: Vec::new() }
	}
}

// TODO: Add function for generating SnarkWitness from ParamsKzg and Circuit
// TODO: Use SnarkWitness inside Aggregator new function, along Svk, instances,
// and as_proof
