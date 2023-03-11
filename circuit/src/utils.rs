//! Helper functions for generating params, pk/vk pairs, creating and verifying
//! proofs, etc.

use halo2::{
	circuit::AssignedCell,
	halo2curves::{
		pairing::{Engine, MultiMillerLoop},
		serde::SerdeObject,
		FieldExt,
	},
	plonk::{
		create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, Error, ProvingKey, VerifyingKey,
	},
	poly::{
		commitment::{CommitmentScheme, Params, ParamsProver},
		kzg::{
			commitment::{KZGCommitmentScheme, ParamsKZG},
			multiopen::{ProverGWC, VerifierGWC},
			strategy::AccumulatorStrategy,
		},
		VerificationStrategy,
	},
	transcript::{
		Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
	},
};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::Rng;
use std::{fmt::Debug, fs::write, io::Read, time::Instant};

use crate::integer::rns::fe_to_big;

/// Returns boolean value from the assigned cell value
pub fn assigned_as_bool<F: FieldExt>(bit: AssignedCell<F, F>) -> bool {
	let bit_value = bit.value();
	let mut is_one = false;
	bit_value.map(|f| {
		is_one = F::one() == *f;
		f
	});
	is_one
}

/// Converts given bytes to the bits.
pub fn to_bits<const B: usize>(num: [u8; 32]) -> [bool; B] {
	let mut bits = [false; B];
	for i in 0..B {
		bits[i] = num[i / 8] & (1 << (i % 8)) != 0;
	}
	bits
}

/// Converts given field element to the bits.
pub fn field_to_bits<const B: usize, F: FieldExt>(num: F) -> [bool; B] {
	let mut bits = [false; B];
	let big = fe_to_big(num);
	for i in 0..B {
		bits[i] = big.clone() & (BigUint::one() << i) != BigUint::zero();
	}
	bits
}

/// Convert bytes array to a wide representation of 64 bytes
pub fn to_wide(b: &[u8]) -> [u8; 64] {
	let mut bytes = [0u8; 64];
	bytes[..b.len()].copy_from_slice(b);
	bytes
}

/// Convert bytes array to a short representation of 32 bytes
pub fn to_short(b: &[u8]) -> [u8; 32] {
	let mut bytes = [0u8; 32];
	bytes[..b.len()].copy_from_slice(b);
	bytes
}

/// Converts field element to string
pub fn field_to_string<F: FieldExt>(f: &F) -> String {
	let bytes = f.to_repr();
	let bn_f = BigUint::from_bytes_le(bytes.as_ref());
	bn_f.to_string()
}

/// Generate parameters with polynomial degree = `k`.
pub fn generate_params<E: Engine + Debug>(k: u32) -> ParamsKZG<E>
where
	E::G1Affine: SerdeObject,
	E::G2Affine: SerdeObject,
{
	ParamsKZG::<E>::new(k)
}

/// Write parameters to a file.
pub fn write_params<E: Engine + Debug>(params: &ParamsKZG<E>, path: &str)
where
	E::G1Affine: SerdeObject,
	E::G2Affine: SerdeObject,
{
	let mut buffer: Vec<u8> = Vec::new();
	params.write(&mut buffer).unwrap();
	write(path, buffer).unwrap();
}

/// Read parameters from a file.
pub fn read_params<E: Engine + Debug>(path: &str) -> ParamsKZG<E>
where
	E::G1Affine: SerdeObject,
	E::G2Affine: SerdeObject,
{
	let mut buffer: Vec<u8> = Vec::new();
	let mut file = std::fs::File::open(path).unwrap();
	file.read_to_end(&mut buffer).unwrap();
	ParamsKZG::<E>::read(&mut &buffer[..]).unwrap()
}

/// Proving/verifying key generation.
pub fn keygen<E: Engine + Debug, C: Circuit<E::Scalar>>(
	params: &ParamsKZG<E>, circuit: C,
) -> Result<ProvingKey<<E as Engine>::G1Affine>, Error>
where
	E::G1Affine: SerdeObject,
	E::G2Affine: SerdeObject,
{
	let vk = keygen_vk::<<E as Engine>::G1Affine, ParamsKZG<E>, _>(params, &circuit)?;
	let pk = keygen_pk::<<E as Engine>::G1Affine, ParamsKZG<E>, _>(params, vk, &circuit)?;

	Ok(pk)
}

/// Helper function for finalizing verification
// Rust compiler can't infer the type, so we need to make a helper function
pub fn finalize_verify<
	'a,
	E: MultiMillerLoop + Debug,
	V: VerificationStrategy<'a, KZGCommitmentScheme<E>, VerifierGWC<'a, E>>,
>(
	v: V,
) -> bool
where
	E::G1Affine: SerdeObject,
	E::G2Affine: SerdeObject,
{
	v.finalize()
}

/// Make a proof for generic circuit.
pub fn prove<E: Engine + Debug, C: Circuit<E::Scalar>, R: Rng + Clone>(
	params: &ParamsKZG<E>, circuit: C,
	pub_inps: &[&[<KZGCommitmentScheme<E> as CommitmentScheme>::Scalar]],
	pk: &ProvingKey<E::G1Affine>, rng: &mut R,
) -> Result<Vec<u8>, Error>
where
	E::G1Affine: SerdeObject,
	E::G2Affine: SerdeObject,
{
	let mut transcript = Blake2bWrite::<_, E::G1Affine, Challenge255<_>>::init(vec![]);
	create_proof::<KZGCommitmentScheme<E>, ProverGWC<_>, _, _, _, _>(
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

/// Verify a proof for generic circuit.
pub fn verify<E: MultiMillerLoop + Debug>(
	params: &ParamsKZG<E>, pub_inps: &[&[<KZGCommitmentScheme<E> as CommitmentScheme>::Scalar]],
	proof: &[u8], vk: &VerifyingKey<E::G1Affine>,
) -> Result<bool, Error>
where
	E::G1Affine: SerdeObject,
	E::G2Affine: SerdeObject,
{
	let strategy = AccumulatorStrategy::<E>::new(params);
	let mut transcript = Blake2bRead::<_, E::G1Affine, Challenge255<_>>::init(proof);
	let output = verify_proof::<KZGCommitmentScheme<E>, VerifierGWC<E>, _, _, _>(
		params,
		vk,
		strategy,
		&[pub_inps],
		&mut transcript,
	)?;

	Ok(finalize_verify(output))
}

/// Helper function for doing proof and verification at the same time.
pub fn prove_and_verify<E: MultiMillerLoop + Debug, C: Circuit<E::Scalar> + Clone, R: Rng + Clone>(
	params: ParamsKZG<E>, circuit: C,
	pub_inps: &[&[<KZGCommitmentScheme<E> as CommitmentScheme>::Scalar]], rng: &mut R,
) -> Result<bool, Error>
where
	E::G1Affine: SerdeObject,
	E::G2Affine: SerdeObject,
{
	let pk = keygen(&params, circuit.clone())?;
	let start = Instant::now();
	let proof = prove(&params, circuit, pub_inps, &pk, rng)?;
	let end = start.elapsed();
	println!("Proving time: {:?}", end);
	let res = verify(&params, pub_inps, &proof[..], pk.get_vk())?;

	Ok(res)
}
