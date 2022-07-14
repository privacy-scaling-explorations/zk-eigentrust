use super::MIN_SCORE;
use crate::{EigenError, Epoch};
use eigen_trust_circuit::{
	ecdsa::{generate_signature, SigData},
	halo2wrong::{
		curves::{
			bn256::{Bn256, Fr as Bn256Scalar, G1Affine},
			group::{Curve, Group},
			secp256k1::{Fq as Secp256k1Scalar, Secp256k1Affine},
			CurveAffine, FieldExt,
		},
		halo2::{
			plonk::{ProvingKey, VerifyingKey},
			poly::kzg::commitment::ParamsKZG,
		},
	},
	poseidon::{native::Poseidon, params::bn254_5x5::Params5x5Bn254},
	utils::{prove, verify},
	EigenTrustCircuit,
};
use libp2p::core::{identity::Keypair as IdentityKeypair, PublicKey as IdentityPublicKey};
use rand::thread_rng;
use super::utils::{convert_keypair, convert_pubkey, to_wide};

pub type Posedion5x5 = Poseidon<Bn256Scalar, 5, Params5x5Bn254>;
pub const SCALE: f64 = 100000000.;

#[derive(Clone, Debug, PartialEq)]
pub struct Opinion<const N: usize> {
	pub(crate) k: Epoch,
	pub(crate) sig_i: SigData<Secp256k1Scalar>,
	pub(crate) op: f64,
	pub(crate) proof_bytes: Vec<u8>,
}

impl<const N: usize> Opinion<N> {
	pub fn new(k: Epoch, sig_i: SigData<Secp256k1Scalar>, op: f64, proof_bytes: Vec<u8>) -> Self {
		Self {
			k,
			sig_i,
			op,
			proof_bytes,
		}
	}

	/// Creates a new opinion.
	pub fn generate(
		kp: &IdentityKeypair,
		pubkey_v: &IdentityPublicKey,
		k: Epoch,
		op_ji: [f64; N],
		c_v: f64,
		params: &ParamsKZG<Bn256>,
		pk: &ProvingKey<G1Affine>,
	) -> Result<Self, EigenError> {
		let mut rng = thread_rng();

		let keypair = convert_keypair(kp)?;
		let pubkey_i = keypair.public().to_owned();
		let pubkey_v = convert_pubkey(pubkey_v)?;

		let pk_v_x = Bn256Scalar::from_bytes_wide(&to_wide(pubkey_v.x.to_bytes()));
		let pk_v_y = Bn256Scalar::from_bytes_wide(&to_wide(pubkey_v.y.to_bytes()));
		let epoch_f = Bn256Scalar::from_u128(u128::from(k.0));

		// Turn into scaled values and round the to avoid rounding errors.
		let op_ji_scaled = op_ji.map(|op| (op * SCALE).round());
		let c_v_scaled = (c_v * SCALE).round();
		let min_score_scaled = (MIN_SCORE * SCALE).round();

		let t_i_scaled = op_ji_scaled
			.iter()
			.fold(min_score_scaled, |acc, op| acc + op);
		let op_v_scaled = t_i_scaled * c_v_scaled;
		// Unscale the value.
		let op_v_unscaled = op_v_scaled / (SCALE * SCALE);

		let min_score = Bn256Scalar::from_u128(min_score_scaled as u128);
		let op_ji_f = op_ji_scaled.map(|op| Bn256Scalar::from_u128(op as u128));
		let c_v_f = Bn256Scalar::from_u128(c_v_scaled as u128);
		let op_v_f = Bn256Scalar::from_u128(op_v_scaled as u128);

		let m_hash_input = [Bn256Scalar::zero(), epoch_f, pk_v_x, pk_v_y, op_v_f];
		let pos = Posedion5x5::new(m_hash_input);
		let out = pos.permute()[0];
		let m_hash = Secp256k1Scalar::from_bytes(&out.to_bytes()).unwrap();
		let sig_i = generate_signature(keypair, m_hash, &mut rng)
			.map_err(|_| EigenError::SignatureError)?;

		let aux_generator =
			<Secp256k1Affine as CurveAffine>::CurveExt::random(&mut rng).to_affine();
		let circuit =
			EigenTrustCircuit::new(pubkey_i, sig_i, op_ji_f, c_v_f, min_score, aux_generator);

		let r = Bn256Scalar::from_bytes_wide(&to_wide(sig_i.r.to_bytes()));
		let s = Bn256Scalar::from_bytes_wide(&to_wide(sig_i.s.to_bytes()));
		let m_hash = Bn256Scalar::from_bytes_wide(&to_wide(sig_i.m_hash.to_bytes()));
		let pk_ix = Bn256Scalar::from_bytes_wide(&to_wide(pubkey_i.x.to_bytes()));
		let pk_iy = Bn256Scalar::from_bytes_wide(&to_wide(pubkey_i.y.to_bytes()));

		let pub_ins = vec![op_v_f, r, s, m_hash, pk_ix, pk_iy];

		let proof_bytes = prove(params, circuit.clone(), &[&pub_ins], pk, &mut rng)
			.map_err(|_| EigenError::ProvingError)?;

		// Sanity check
		let proof_res = verify(params, &[&pub_ins], &proof_bytes, pk.get_vk())
			.map_err(|_| EigenError::VerificationError)?;
		assert!(proof_res);

		Ok(Self {
			k,
			sig_i,
			op: op_v_unscaled,
			proof_bytes,
		})
	}

	pub fn empty() -> Self {
		let k = Epoch(0);
		let sig_i = SigData::empty();
		let op_v = 0.;

		let proof_bytes = Vec::new();

		Self {
			k,
			sig_i,
			op: op_v,
			proof_bytes,
		}
	}

	/// Verifies the proof.
	pub fn verify(
		&self,
		pubkey_p: &IdentityPublicKey,
		pubkey_v: &IdentityPublicKey,
		params: &ParamsKZG<Bn256>,
		vk: &VerifyingKey<G1Affine>,
	) -> Result<bool, EigenError> {
		if self.k == Epoch(0) {
			return Ok(true);
		}

		let pk_p = convert_pubkey(pubkey_p)?;
		let pk_v = convert_pubkey(pubkey_v)?;

		let epoch_f = Bn256Scalar::from_u128(u128::from(self.k.0));
		let pk_v_x = Bn256Scalar::from_bytes_wide(&to_wide(pk_v.x.to_bytes()));
		let pk_v_y = Bn256Scalar::from_bytes_wide(&to_wide(pk_v.y.to_bytes()));
		let op_v_f = Bn256Scalar::from_u128((self.op * SCALE * SCALE).round() as u128);

		let m_hash_input = [Bn256Scalar::zero(), epoch_f, pk_v_x, pk_v_y, op_v_f];
		let pos = Posedion5x5::new(m_hash_input);
		let out = pos.permute()[0];
		let m_hash = Secp256k1Scalar::from_bytes(&out.to_bytes()).unwrap();

		// TODO: Do inside the circuit
		let sig_res = self.sig_i.m_hash == m_hash;

		let r = Bn256Scalar::from_bytes_wide(&to_wide(self.sig_i.r.to_bytes()));
		let s = Bn256Scalar::from_bytes_wide(&to_wide(self.sig_i.s.to_bytes()));
		let m_hash = Bn256Scalar::from_bytes_wide(&to_wide(self.sig_i.m_hash.to_bytes()));
		let pk_ix = Bn256Scalar::from_bytes_wide(&to_wide(pk_p.x.to_bytes()));
		let pk_iy = Bn256Scalar::from_bytes_wide(&to_wide(pk_p.y.to_bytes()));

		let pub_ins = vec![op_v_f, r, s, m_hash, pk_ix, pk_iy];

		let proof_res = verify(params, &[&pub_ins], &self.proof_bytes, vk)
			.map_err(|_| EigenError::VerificationError)?;

		Ok(sig_res && proof_res)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use eigen_trust_circuit::{
		halo2wrong::halo2::poly::commitment::ParamsProver,
		utils::{keygen, random_circuit},
	};

	const N: usize = 3;

	#[test]
	fn should_verify_empty_opinion() {
		let rng = &mut thread_rng();
		let op = Opinion::<N>::empty();
		let local_keypair = IdentityKeypair::generate_secp256k1();
		let local_pubkey = local_keypair.public();

		let keypair_v = IdentityKeypair::generate_secp256k1();
		let pubkey_v = keypair_v.public();
		let params = ParamsKZG::<Bn256>::new(18);
		let min_score = Bn256Scalar::from_u128((MIN_SCORE * SCALE).round() as u128);
		let random_circuit =
			random_circuit::<Bn256, Secp256k1Affine, _, N>(min_score, &mut rng.clone());
		let pk = keygen(&params, &random_circuit).unwrap();
		let res = op
			.verify(&local_pubkey, &pubkey_v, &params, &pk.get_vk())
			.unwrap();
		assert!(res);
	}

	#[test]
	fn test_new_proof_generate() {
		let rng = &mut thread_rng();
		let local_keypair = IdentityKeypair::generate_secp256k1();
		let local_pubkey = local_keypair.public();

		let keypair_v = IdentityKeypair::generate_secp256k1();
		let pubkey_v = keypair_v.public();

		let epoch = Epoch(1);
		let op_ji = [0.1; N];
		let c_v = 0.1;
		let min_score = Bn256Scalar::from_u128((MIN_SCORE * SCALE).round() as u128);

		let params = ParamsKZG::<Bn256>::new(18);
		let random_circuit =
			random_circuit::<Bn256, Secp256k1Affine, _, N>(min_score, &mut rng.clone());
		let pk = keygen(&params, &random_circuit).unwrap();
		let proof =
			Opinion::<N>::generate(&local_keypair, &pubkey_v, epoch, op_ji, c_v, &params, &pk)
				.unwrap();

		assert!(proof
			.verify(&local_pubkey, &pubkey_v, &params, pk.get_vk())
			.unwrap());
	}
}
