use crate::{
	integer::native::Integer,
	params::hasher::poseidon_bn254_5x5::Params,
	params::rns::bn256::Bn256_4_68,
	poseidon::native::sponge::PoseidonSponge,
	verifier::{
		gen_pk,
		loader::native::{NUM_BITS, NUM_LIMBS},
		transcript::native::{NativeTranscriptRead, NativeTranscriptWrite, WIDTH},
	},
};
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
use itertools::Itertools;
use rand::{thread_rng, RngCore};
use snark_verifier::{
	pcs::{
		kzg::{Gwc19, KzgAccumulator, KzgAs},
		AccumulationSchemeProver,
	},
	system::halo2::{compile, Config},
	verifier::{plonk::PlonkProtocol, SnarkVerifier},
};

use super::{Aggregator, Psv};

#[derive(Clone)]
/// Snark structure
pub struct Snark {
	/// Protocol
	pub protocol: PlonkProtocol<G1Affine>,
	/// Instances
	pub instances: Vec<Vec<Fr>>,
	/// Proof
	pub proof: Vec<u8>,
}

impl Snark {
	/// Create a new Snark
	pub fn new<C: Circuit<Fr>, R: RngCore>(
		params: &ParamsKZG<Bn256>, circuit: C, instances: Vec<Vec<Fr>>, rng: &mut R,
	) -> Self {
		let pk = gen_pk(params, &circuit);
		let config = Config::kzg().with_num_instance(vec![instances.len()]);

		let protocol = compile(params, pk.get_vk(), config);

		let instances_slice: Vec<&[Fr]> = instances.iter().map(|x| x.as_slice()).collect();
		let mut transcript = NativeTranscriptWrite::<
			_,
			G1Affine,
			Bn256_4_68,
			PoseidonSponge<Fr, WIDTH, Params>,
		>::new(Vec::new());
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

impl Aggregator {
	/// Create a new aggregator.
	pub fn new(params: &ParamsKZG<Bn256>, snarks: Vec<Snark>) -> Self {
		let svk = params.get_g()[0].into();

		let mut plonk_proofs = Vec::new();
		for snark in &snarks {
			let mut transcript_read: NativeTranscriptRead<
				_,
				G1Affine,
				Bn256_4_68,
				PoseidonSponge<Fr, WIDTH, Params>,
			> = NativeTranscriptRead::init(snark.proof.as_slice());

			let proof = Psv::read_proof(
				&svk, &snark.protocol, &snark.instances, &mut transcript_read,
			)
			.unwrap();
			let res = Psv::verify(&svk, &snark.protocol, &snark.instances, &proof).unwrap();

			plonk_proofs.extend(res);
		}

		let mut transcript_write = NativeTranscriptWrite::<
			Vec<u8>,
			G1Affine,
			Bn256_4_68,
			PoseidonSponge<Fr, WIDTH, Params>,
		>::new(Vec::new());
		let rng = &mut thread_rng();
		let accumulator = KzgAs::<Bn256, Gwc19>::create_proof(
			&Default::default(),
			&plonk_proofs,
			&mut transcript_write,
			rng,
		)
		.unwrap();
		let as_proof = transcript_write.finalize();

		let KzgAccumulator { lhs, rhs } = accumulator;
		let accumulator_limbs = [lhs.x, lhs.y, rhs.x, rhs.y]
			.map(|v| Integer::<_, _, NUM_LIMBS, NUM_BITS, Bn256_4_68>::from_w(v).limbs)
			.concat();

		Self {
			svk,
			snarks: snarks.into_iter().map_into().collect(),
			instances: accumulator_limbs,
			as_proof: Some(as_proof),
		}
	}
}
