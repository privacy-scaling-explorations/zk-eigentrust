use ecc::halo2::plonk::{ProvingKey, VerifyingKey};
use halo2wrong::{
	curves::pairing::{Engine, MultiMillerLoop},
	halo2::{
		plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, Error},
		poly::{
			commitment::{Params, ParamsProver},
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
use std::{
	fmt::Debug,
	fs::{write, File},
	io::Read,
};

pub fn generate_params<E: MultiMillerLoop + Debug>(k: u32) -> ParamsKZG<E> {
	ParamsKZG::<E>::new(k)
}

pub fn write_params<E: MultiMillerLoop + Debug>(params: &ParamsKZG<E>, path: &str) {
	let mut buffer: Vec<u8> = Vec::new();
	params.write(&mut buffer);
	write(path, buffer).unwrap();
}

pub fn read_params<E: MultiMillerLoop + Debug>(path: &str) -> ParamsKZG<E> {
	let mut buffer: Vec<u8> = Vec::new();
	let mut file = std::fs::File::open(path).unwrap();
	file.read_to_end(&mut buffer).unwrap();
	ParamsKZG::<E>::read(&mut &buffer[..]).unwrap()
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

pub fn prove_and_verify<E: MultiMillerLoop + Debug, C: Circuit<E::Scalar>, R: Rng + Clone>(
	params: ParamsKZG<E>,
	circuit: C,
	rng: &mut R,
) -> Result<bool, Error> {
	let pk = keygen(&params, &circuit)?;

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
