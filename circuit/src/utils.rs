use std::fmt::Debug;

use halo2wrong::{
	curves::pairing::MultiMillerLoop,
	halo2::{
		plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, Error},
		poly::{
			commitment::ParamsProver,
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

pub fn prove_and_verify<E: MultiMillerLoop + Debug, C: Circuit<E::Scalar>, R: Rng + Clone>(
	k: u32,
	circuit: C,
	rng: &mut R,
) -> Result<bool, Error> {
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
		&mut transcript,
	)?;

	Ok(finalize_verify(output))
}
