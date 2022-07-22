use super::pubkey::Pubkey;
use crate::{
	constants::*,
	peer::utils::{extract_sk_limbs, to_wide_bytes},
	EigenError, Epoch,
};
use bs58::decode::Error as Bs58Error;
use eigen_trust_circuit::{
	halo2wrong::{
		curves::{
			bn256::{Bn256, Fr as Bn256Scalar, G1Affine},
			FieldExt,
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
use libp2p::core::identity::Keypair as IdentityKeypair;
use rand::thread_rng;

pub type Posedion5x5 = Poseidon<Bn256Scalar, 5, Params5x5Bn254>;
pub type ETCircuit =
	EigenTrustCircuit<Bn256Scalar, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params5x5Bn254>;
pub const SCALE: f64 = 100000000.;

#[derive(Clone, Debug, PartialEq)]
pub struct Opinion {
	pub(crate) epoch: Epoch,
	pub(crate) op: f64,
	pub(crate) proof_bytes: Vec<u8>,
}

impl Opinion {
	pub fn new(epoch: Epoch, op: f64, proof_bytes: Vec<u8>) -> Self {
		Self {
			epoch,
			op,
			proof_bytes,
		}
	}

	/// Creates a new opinion.
	pub fn generate(
		kp: &IdentityKeypair,
		pubkey_v: &Pubkey,
		k: Epoch,
		op_ji: [f64; MAX_NEIGHBORS],
		c_v: f64,
		params: &ParamsKZG<Bn256>,
		pk: &ProvingKey<G1Affine>,
	) -> Result<Self, EigenError> {
		let mut rng = thread_rng();

		let sk = extract_sk_limbs(kp)?;
		let input = [Bn256Scalar::zero(), sk[0], sk[1], sk[2], sk[3]];
		let pos = Posedion5x5::new(input);
		let pk_i = pos.permute()[0];

		let pk_v = pubkey_v.value();
		let epoch_f = Bn256Scalar::from_u128(u128::from(k.0));

		// Turn into scaled values and round the to avoid rounding errors.
		let op_ji_scaled = op_ji.map(|op| (op * SCALE).round());
		let c_v_scaled = (c_v * SCALE).round();

		let t_i_scaled = op_ji_scaled.iter().fold(0., |acc, op| acc + op);
		let op_v_scaled = t_i_scaled * c_v_scaled;
		// Unscale the value.
		let op_v_unscaled = op_v_scaled / (SCALE * SCALE);

		let op_ji_f = op_ji_scaled.map(|op| Bn256Scalar::from_u128(op as u128));
		let c_v_f = Bn256Scalar::from_u128(c_v_scaled as u128);
		let op_v_f = Bn256Scalar::from_u128(op_v_scaled as u128);

		let m_hash_input = [Bn256Scalar::zero(), epoch_f, op_v_f, pk_v, pk_i];
		let pos = Posedion5x5::new(m_hash_input);
		let m_hash = pos.permute()[0];

		let bootstrap_pubkeys = BOOTSTRAP_PEERS
			.try_map(|key| {
				let bytes = &bs58::decode(key).into_vec()?;
				Ok(Bn256Scalar::from_bytes_wide(&to_wide_bytes(&bytes)))
			})
			.map_err(|_: Bs58Error| EigenError::InvalidBootstrapPubkey)?;
		let bootstrap_score = Bn256Scalar::from_u128((BOOTSTRAP_SCORE * SCALE).round() as u128);
		let genesis_epoch = Bn256Scalar::from_u128(u128::from(GENESIS_EPOCH));

		let circuit = ETCircuit::new(
			pk_v,
			epoch_f,
			sk,
			op_ji_f,
			c_v_f,
			bootstrap_pubkeys,
			bootstrap_score,
			genesis_epoch,
		);

		let pub_ins = vec![m_hash];

		let proof_bytes = prove(params, circuit.clone(), &[&pub_ins], pk, &mut rng)
			.map_err(|_| EigenError::ProvingError)?;

		// Sanity check
		let proof_res = verify(params, &[&pub_ins], &proof_bytes, pk.get_vk())
			.map_err(|_| EigenError::VerificationError)?;
		assert!(proof_res);

		Ok(Self {
			epoch: k,
			op: op_v_unscaled,
			proof_bytes,
		})
	}

	pub fn empty() -> Self {
		let epoch = Epoch(0);
		let op_v = 0.;

		let proof_bytes = Vec::new();

		Self {
			epoch,
			op: op_v,
			proof_bytes,
		}
	}

	/// Verifies the proof.
	pub fn verify(
		&self,
		pubkey_p: &Pubkey,
		kp: &IdentityKeypair,
		params: &ParamsKZG<Bn256>,
		vk: &VerifyingKey<G1Affine>,
	) -> Result<bool, EigenError> {
		if self.op == 0. {
			return Ok(true);
		}

		let pk_p = pubkey_p.value();
		let sk = extract_sk_limbs(kp)?;
		let input = [Bn256Scalar::zero(), sk[0], sk[1], sk[2], sk[3]];
		let pos = Posedion5x5::new(input);
		let pk_v = pos.permute()[0];

		let epoch_f = Bn256Scalar::from_u128(u128::from(self.epoch.0));
		let op_v_f = Bn256Scalar::from_u128((self.op * SCALE * SCALE).round() as u128);

		let m_hash_input = [Bn256Scalar::zero(), epoch_f, op_v_f, pk_v, pk_p];
		let pos = Posedion5x5::new(m_hash_input);
		let m_hash = pos.permute()[0];

		let pub_ins = vec![m_hash];

		let proof_res = verify(params, &[&pub_ins], &self.proof_bytes, vk)
			.map_err(|_| EigenError::VerificationError)?;

		Ok(proof_res)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use eigen_trust_circuit::{
		halo2wrong::halo2::poly::commitment::ParamsProver,
		utils::{keygen, random_circuit},
	};

	#[test]
	fn should_verify_empty_opinion() {
		let rng = &mut thread_rng();
		let op = Opinion::empty();
		let local_keypair = IdentityKeypair::generate_secp256k1();
		let local_pubkey = Pubkey::from_keypair(&local_keypair).unwrap();

		let keypair_v = IdentityKeypair::generate_secp256k1();
		let params = ParamsKZG::<Bn256>::new(18);
		let random_circuit =
			random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params5x5Bn254>(rng);
		let pk = keygen(&params, &random_circuit).unwrap();
		let res = op
			.verify(&local_pubkey, &keypair_v, &params, &pk.get_vk())
			.unwrap();
		assert!(res);
	}

	#[test]
	fn test_new_proof_generate() {
		let rng = &mut thread_rng();
		let local_keypair = IdentityKeypair::generate_secp256k1();
		let local_pubkey = Pubkey::from_keypair(&local_keypair).unwrap();

		let keypair_v = IdentityKeypair::generate_secp256k1();
		let pubkey_v = Pubkey::from_keypair(&keypair_v).unwrap();

		let epoch = Epoch(1);
		let op_ji = [0.1; MAX_NEIGHBORS];
		let c_v = 0.1;

		let params = ParamsKZG::<Bn256>::new(18);
		let random_circuit =
			random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params5x5Bn254>(rng);
		let pk = keygen(&params, &random_circuit).unwrap();
		let proof =
			Opinion::generate(&local_keypair, &pubkey_v, epoch, op_ji, c_v, &params, &pk).unwrap();

		assert!(proof
			.verify(&local_pubkey, &keypair_v, &params, pk.get_vk())
			.unwrap());
	}
}
