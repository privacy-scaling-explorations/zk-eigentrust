use halo2::{
	halo2curves::bn256::{Bn256, Fr, G1Affine},
	plonk::{create_proof, Circuit},
	poly::{
		commitment::ParamsProver,
		kzg::{
			commitment::{KZGCommitmentScheme, ParamsKZG},
			multiopen::ProverGWC,
		},
	},
	transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use rand::{thread_rng, RngCore};
use snark_verifier::{
	pcs::{
		kzg::{Gwc19, KzgAccumulator, KzgAs, KzgSuccinctVerifyingKey},
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
	gen_pk,
	loader::native::{NUM_BITS, NUM_LIMBS},
	transcript::native::{PoseidonRead, PoseidonWrite},
};

type PSV = PlonkSuccinctVerifier<KzgAs<Bn256, Gwc19>>;
type SVK = KzgSuccinctVerifyingKey<G1Affine>;

#[derive(Clone)]
/// Snark witness structure
pub struct Snark {
	protocol: PlonkProtocol<G1Affine>,
	instances: Vec<Vec<Fr>>,
	proof: Vec<u8>,
}

impl Snark {
	fn new<C: Circuit<Fr>, R: RngCore>(
		params: &ParamsKZG<Bn256>, circuit: C, instances: Vec<Vec<Fr>>, rng: &mut R,
	) -> Self {
		let pk = gen_pk(params, &circuit);
		let protocol = compile(
			params,
			pk.get_vk(),
			Config::kzg().with_num_instance(vec![1]),
		);

		let instances_slice: Vec<&[Fr]> = instances.iter().map(|x| x.as_slice()).collect();
		let mut transcript = PoseidonWrite::<_, G1Affine, Bn256_4_68, Params>::new(Vec::new());
		create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, _, _>(
			params,
			&pk,
			&[circuit],
			&[instances_slice.as_slice()],
			rng,
			&mut transcript,
		)
		.unwrap();
		let proof = transcript.finalize();
		Self { protocol, instances, proof }
	}
}

// TODO: Make SnarkWitness and functions to convert from Snark to SnarkWitness,
// without witness function
struct Aggregator {
	svk: SVK,
	snarks: Vec<Snark>,
	instances: Vec<Fr>,
	as_proof: Vec<u8>,
}

impl Aggregator {
	pub fn new(params: &ParamsKZG<Bn256>, snarks: Vec<Snark>) -> Self {
		let svk = params.get_g()[0].into();

		let mut plonk_proofs = Vec::new();
		for snark in &snarks {
			let mut transcript_read: PoseidonRead<_, G1Affine, Bn256_4_68, Params> =
				PoseidonRead::init(snark.proof.as_slice());
			let proof = PSV::read_proof(
				&svk, &snark.protocol, &snark.instances, &mut transcript_read,
			)
			.unwrap();
			let res = PSV::verify(&svk, &snark.protocol, &snark.instances, &proof).unwrap();
			plonk_proofs.extend(res);
		}

		let (accumulator, as_proof) = {
			let mut transcript_write =
				PoseidonWrite::<Vec<u8>, G1Affine, Bn256_4_68, Params>::new(Vec::new());
			let rng = &mut thread_rng();
			let accumulator = KzgAs::<Bn256, Gwc19>::create_proof(
				&Default::default(),
				&plonk_proofs,
				&mut transcript_write,
				rng,
			)
			.unwrap();
			(accumulator, transcript_write.finalize())
		};

		let KzgAccumulator { lhs, rhs } = accumulator;
		let instances = [lhs.x, lhs.y, rhs.x, rhs.y]
			.map(|v| Integer::<_, _, NUM_LIMBS, NUM_BITS, Bn256_4_68>::from_w(v).limbs)
			.concat();

		Self { svk, snarks, instances, as_proof }
	}
}
