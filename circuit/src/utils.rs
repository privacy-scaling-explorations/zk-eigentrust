use std::fmt::Debug;

use rand::Rng;
use halo2wrong::{
	halo2::plonk::{Circuit, Error},
	halo2::poly::commitment::ParamsProver,
	halo2::poly::kzg::commitment::{ParamsKZG, KZGCommitmentScheme},
	halo2::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK},
	halo2::poly::kzg::strategy::BatchVerifier,
	halo2::poly::VerificationStrategy,
	halo2::transcript::TranscriptReadBuffer,
	halo2::transcript::TranscriptWriterBuffer,
	halo2::plonk::{verify_proof, create_proof, keygen_pk, keygen_vk},
	halo2::transcript::{Blake2bWrite, Blake2bRead, Challenge255},
	curves::pairing::MultiMillerLoop,
};

// Rust compiler can't infer the type, so we need to make a helper function
pub fn finalize_verify<
	'a,
	E: MultiMillerLoop + Debug,
	R: Rng + Clone,
	V: VerificationStrategy<'a, KZGCommitmentScheme<E>, VerifierSHPLONK<'a, E>, R>
>(v: V) -> bool {
	v.finalize()
}

pub fn prove_and_verify<
	E: MultiMillerLoop + Debug,
	C: Circuit<E::Scalar>,
	R: Rng + Clone
>(k: u32, circuit: C, rng: &mut R) -> Result<bool, Error> {
	let params = ParamsKZG::<E>::new(k);
	let vk = keygen_vk::<KZGCommitmentScheme<E>, _>(&params, &circuit)?;
	let pk = keygen_pk::<KZGCommitmentScheme<E>, _>(&params, vk, &circuit)?;

	let mut transcript = Blake2bWrite::<_, E::G1Affine, Challenge255<_>>::init(vec![]);
	create_proof::<KZGCommitmentScheme<E>, ProverSHPLONK<_>, _, _, _, _>(
		&params,
		&pk,
		&[circuit],
		&[],
		rng.clone(),
		&mut transcript,
	)?;

	let proof = transcript.finalize();

	let strategy = BatchVerifier::<E, R>::new(&params, rng.clone());
	let mut transcript = Blake2bRead::<_, E::G1Affine, Challenge255<_>>::init(&proof[..]);
	let output = verify_proof::<KZGCommitmentScheme<E>, _, _, VerifierSHPLONK<E>, _, _>(
		&params,
		pk.get_vk(),
		strategy,
		&[],
		&mut transcript
	)?;

	Ok(finalize_verify(output))
}