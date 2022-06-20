use crate::{
	ecdsa::native::{generate_signature, Keypair},
	EigenTrustCircuit,
};
use halo2wrong::{
	curves::{
		group::{Curve, Group},
		pairing::{Engine, MultiMillerLoop},
		CurveAffine,
	},
	halo2::{
		arithmetic::Field,
		plonk::{
			create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, Error, ProvingKey,
			VerifyingKey,
		},
		poly::{
			commitment::{CommitmentScheme, Params, ParamsProver},
			kzg::{
				commitment::{KZGCommitmentScheme, ParamsKZG},
				multiopen::{ProverSHPLONK, VerifierSHPLONK},
				strategy::BatchVerifier,
			},
			VerificationStrategy,
		},
		transcript::{
			Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
		},
	},
};
use rand::Rng;
use std::{fmt::Debug, fs::write, io::Read};

pub fn generate_params<E: MultiMillerLoop + Debug>(k: u32) -> ParamsKZG<E> {
	ParamsKZG::<E>::new(k)
}

pub fn write_params<E: MultiMillerLoop + Debug>(params: &ParamsKZG<E>, path: &str) {
	let mut buffer: Vec<u8> = Vec::new();
	params.write(&mut buffer).unwrap();
	write(path, buffer).unwrap();
}

pub fn read_params<E: MultiMillerLoop + Debug>(path: &str) -> ParamsKZG<E> {
	let mut buffer: Vec<u8> = Vec::new();
	let mut file = std::fs::File::open(path).unwrap();
	file.read_to_end(&mut buffer).unwrap();
	ParamsKZG::<E>::read(&mut &buffer[..]).unwrap()
}

pub fn random_circuit<
	E: MultiMillerLoop + Debug,
	N: CurveAffine,
	R: Rng + Clone,
	const SIZE: usize,
>(
	rng: &mut R,
) -> EigenTrustCircuit<N, <E as Engine>::Scalar, SIZE> {
	let m_hash = N::ScalarExt::random(rng.clone());

	// Data for prover
	let pair_i = Keypair::<N>::new(rng);
	let pubkey_i = pair_i.public().to_owned();
	let sig_i = generate_signature(pair_i, m_hash, rng).unwrap();

	// Data from neighbors of i
	let c_ji = [(); SIZE].map(|_| E::Scalar::random(rng.clone()));
	let t_j = [(); SIZE].map(|_| E::Scalar::random(rng.clone()));
	let pairs = [(); SIZE].map(|_| Keypair::<N>::new(rng));
	let pubkeys = pairs.map(|p| p.public().to_owned());
	let sigs = pairs.map(|p| generate_signature(p, m_hash, rng).unwrap());
	let selectors = [true; SIZE];

	// Aux generator
	let aux_generator = N::CurveExt::random(rng).to_affine();

	let eigen_trust = EigenTrustCircuit::<_, _, SIZE>::new(
		pubkey_i,
		sig_i,
		c_ji,
		t_j,
		pubkeys,
		sigs,
		selectors,
		aux_generator,
	);

	eigen_trust
}

pub fn keygen<E: MultiMillerLoop + Debug, C: Circuit<E::Scalar>>(
	params: &ParamsKZG<E>,
	circuit: &C,
) -> Result<ProvingKey<<E as Engine>::G1Affine>, Error> {
	let vk = keygen_vk::<KZGCommitmentScheme<E>, _>(params, circuit)?;
	let pk = keygen_pk::<KZGCommitmentScheme<E>, _>(params, vk, circuit)?;

	Ok(pk)
}

// Rust compiler can't infer the type, so we need to make a helper function
pub fn finalize_verify<
	'a,
	E: MultiMillerLoop + Debug,
	R: Rng + Clone,
	V: VerificationStrategy<'a, KZGCommitmentScheme<E>, VerifierSHPLONK<'a, E>, R>,
>(
	v: V,
) -> bool {
	v.finalize()
}

pub fn prove<E: MultiMillerLoop + Debug, C: Circuit<E::Scalar>, R: Rng + Clone>(
	params: &ParamsKZG<E>,
	circuit: C,
	pub_inps: &[&[<KZGCommitmentScheme<E> as CommitmentScheme>::Scalar]],
	pk: &ProvingKey<E::G1Affine>,
	rng: &mut R,
) -> Result<Vec<u8>, Error> {
	let mut transcript = Blake2bWrite::<_, E::G1Affine, Challenge255<_>>::init(vec![]);
	create_proof::<KZGCommitmentScheme<E>, ProverSHPLONK<_>, _, _, _, _>(
		params,
		pk,
		&[circuit],
		&[pub_inps],
		rng.clone(),
		&mut transcript,
	)?;

	let proof = transcript.finalize();
	Ok(proof)
}

pub fn verify<E: MultiMillerLoop + Debug, R: Rng + Clone>(
	params: &ParamsKZG<E>,
	pub_inps: &[&[<KZGCommitmentScheme<E> as CommitmentScheme>::Scalar]],
	proof: &[u8],
	vk: &VerifyingKey<E::G1Affine>,
	rng: &mut R,
) -> Result<bool, Error> {
	let strategy = BatchVerifier::<E, R>::new(&params, rng.clone());
	let mut transcript = Blake2bRead::<_, E::G1Affine, Challenge255<_>>::init(proof);
	let output = verify_proof::<KZGCommitmentScheme<E>, _, _, VerifierSHPLONK<E>, _, _>(
		&params,
		vk,
		strategy,
		&[pub_inps],
		&mut transcript,
	)?;

	Ok(finalize_verify(output))
}

pub fn prove_and_verify<E: MultiMillerLoop + Debug, C: Circuit<E::Scalar>, R: Rng + Clone>(
	params: ParamsKZG<E>,
	circuit: C,
	pub_inps: &[&[<KZGCommitmentScheme<E> as CommitmentScheme>::Scalar]],
	rng: &mut R,
) -> Result<bool, Error> {
	let pk = keygen(&params, &circuit)?;
	let proof = prove(&params, circuit, pub_inps, &pk, rng)?;
	let res = verify(&params, pub_inps, &proof[..], pk.get_vk(), rng)?;

	Ok(res)
}
