use super::MAX_NEIGHBORS;
use crate::EigenError;
use eigen_trust_circuit::{
	ecdsa::{generate_signature, Keypair, SigData},
	halo2wrong::{
		curves::{
			bn256::{Bn256, Fr as Bn256Scalar},
			secp256k1::{Fq as Secp256k1Scalar, Secp256k1Affine},
			FieldExt,
		},
		halo2::poly::kzg::commitment::ParamsKZG,
	},
	poseidon::{params::Params5x5Bn254, Poseidon},
	utils::{keygen, prove},
	EigenTrustCircuit,
};
use rand::thread_rng;

use crate::Epoch;

type Posedion5x5 = Poseidon<Bn256Scalar, 5, Params5x5Bn254>;
const SCALE: f64 = 100000000.;

#[derive(Clone)]
pub struct Proof {
	t_i: Bn256Scalar,
	sig_i: SigData<Secp256k1Scalar>,
	c_ji: [Bn256Scalar; MAX_NEIGHBORS],
	t_j: [Bn256Scalar; MAX_NEIGHBORS],
	proof_bytes: Vec<u8>,
}

impl Proof {
	/// Creates a new opinion.
	pub fn new(
		keypair: Keypair<Secp256k1Affine>,
		c_ji: [f64; MAX_NEIGHBORS],
		t_j: [f64; MAX_NEIGHBORS],
		k: Epoch,
		local_trust_score: f64,
		global_trust_score: f64,
		neighbor_sigs: [SigData<Secp256k1Scalar>; MAX_NEIGHBORS],
		neighbor_pubkeys: [Secp256k1Affine; MAX_NEIGHBORS],
		params: &ParamsKZG<Bn256>,
	) -> Result<Self, EigenError> {
		let mut rng = thread_rng();

		let pubkey_i = keypair.public().to_owned();

		let epoch_f = Bn256Scalar::from_u128(u128::from(k.0));
		let t_i = c_ji.zip(t_j).iter().fold(0., |acc, (a, b)| acc + (a * b));
		let t_i_f = Bn256Scalar::from_u128((t_i * SCALE).round() as u128);

		let m_hash_input = [
			Bn256Scalar::zero(),
			Bn256Scalar::from_bytes_wide(&to_wide(pubkey_i.x.to_bytes())),
			Bn256Scalar::from_bytes_wide(&to_wide(pubkey_i.y.to_bytes())),
			epoch_f,
			t_i_f,
		];

		let pos = Posedion5x5::new(m_hash_input);
		let m_hash_op: Option<Secp256k1Scalar> =
			Secp256k1Scalar::from_bytes(&pos.permute()[0].to_bytes()).into();
		let m_hash = m_hash_op.ok_or(EigenError::HashError)?;
		let sig_i = generate_signature(keypair, m_hash, &mut rng)
			.map_err(|_| EigenError::SignatureError)?;

		let c_ji_scaled = c_ji.map(|c| Bn256Scalar::from_u128((c * SCALE).round() as u128));
		let t_j_scaled = t_j.map(|c| Bn256Scalar::from_u128((c * SCALE).round() as u128));

		let aux_generator = Secp256k1Affine::generator();
		let circuit = EigenTrustCircuit::new(
			pubkey_i,
			sig_i,
			c_ji_scaled,
			t_j_scaled,
			neighbor_pubkeys,
			neighbor_sigs,
			aux_generator,
		);

		let pk_ix = Bn256Scalar::from_bytes_wide(&to_wide(pubkey_i.x.to_bytes()));
		let pk_iy = Bn256Scalar::from_bytes_wide(&to_wide(pubkey_i.y.to_bytes()));
		let r = Bn256Scalar::from_bytes_wide(&to_wide(sig_i.r.to_bytes()));
		let s = Bn256Scalar::from_bytes_wide(&to_wide(sig_i.s.to_bytes()));
		let m_hash = Bn256Scalar::from_bytes_wide(&to_wide(sig_i.m_hash.to_bytes()));

		let mut pub_ins = Vec::new();
		pub_ins.push(t_i_f);
		pub_ins.push(pk_ix);
		pub_ins.push(pk_iy);
		pub_ins.push(r);
		pub_ins.push(s);
		pub_ins.push(m_hash);

		for i in 0..MAX_NEIGHBORS {
			pub_ins.push(c_ji_scaled[i]);
		}

		for i in 0..MAX_NEIGHBORS {
			pub_ins.push(t_j_scaled[i]);
		}

		let pk = keygen(params, &circuit).map_err(|_| EigenError::ProvingError)?;
		let proof_bytes = prove(params, circuit, &[&pub_ins], &pk, &mut rng)
			.map_err(|_| EigenError::ProvingError)?;

		Ok(Self {
			t_i: t_i_f,
			sig_i,
			c_ji: c_ji_scaled,
			t_j: t_j_scaled,
			proof_bytes,
		})
	}
}

fn to_wide(p: [u8; 32]) -> [u8; 64] {
	let mut res = [0u8; 64];
	res[..32].copy_from_slice(&p[..]);
	res
}
