//! Helper functions for generating params, pk/vk pairs, creating and verifying
//! proofs, etc.

use halo2::{
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
use rand::Rng;
use serde::{de::DeserializeOwned, Serialize};
use std::{
	env::current_dir,
	fmt::Debug,
	fs::{write, File},
	io::{BufReader, Error as IoError, Read},
	path::Path,
	time::Instant,
};

/// Reads raw bytes from the file
pub fn read_bytes(path: impl AsRef<Path>) -> Vec<u8> {
	let f = File::open(path).unwrap();
	let mut reader = BufReader::new(f);
	let mut buffer = Vec::new();

	// Read file into vector.
	reader.read_to_end(&mut buffer).unwrap();

	buffer
}

/// Reads raw bytes from the file
pub fn read_bytes_data(name: &str) -> Vec<u8> {
	let current_dir = current_dir().unwrap();
	let bin_path = current_dir.join(format!("../data/{}.bin", name));
	let f = File::open(bin_path).unwrap();
	let mut reader = BufReader::new(f);
	let mut buffer = Vec::new();

	// Read file into vector.
	reader.read_to_end(&mut buffer).unwrap();

	buffer
}

/// Write bytes to a file
pub fn write_bytes(bytes: Vec<u8>, path: impl AsRef<Path>) -> Result<(), IoError> {
	write(path, bytes)
}

/// Write bytes to data directory
pub fn write_bytes_data(bytes: Vec<u8>, name: &str) -> Result<(), IoError> {
	let current_dir = current_dir().unwrap();
	let bin_path = current_dir.join(format!("../data/{}.bin", name));
	write(bin_path, bytes)
}

/// Reads yul to file
pub fn write_yul_data(code: String, name: &str) -> Result<(), IoError> {
	let current_dir = current_dir().unwrap();
	let bin_path = current_dir.join(format!("../data/{}.yul", name));
	write(bin_path, code)
}

/// Writes json to fule
pub fn write_json_file<T: Serialize>(json: T, path: impl AsRef<Path>) -> Result<(), IoError> {
	let bytes = serde_json::to_vec(&json)?;
	write(path, bytes)?;
	Ok(())
}

/// Reads the json file and deserialize it into the provided type
pub fn write_json_data<T: Serialize>(json: T, name: &str) -> Result<(), IoError> {
	let current_dir = current_dir()?;
	let json_path = current_dir.join(format!("../data/{}.json", name));
	write_json_file(json, json_path)?;
	Ok(())
}

/// Reads the json file and deserialize it into the provided type
pub fn read_json_file<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T, IoError> {
	let path = path.as_ref();
	let file = std::fs::File::open(path)?;
	let file = std::io::BufReader::new(file);
	let val: T = serde_json::from_reader(file)?;
	Ok(val)
}

/// Reads the json file and deserialize it into the provided type
pub fn read_json_data<T: DeserializeOwned>(name: &str) -> Result<T, IoError> {
	let current_dir = current_dir()?;
	let json_path = current_dir.join(format!("../data/{}.json", name));
	read_json_file(json_path)
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

/// Generate parameters with polynomial degere = `k`.
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
