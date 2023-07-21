use halo2::halo2curves::{bn256::Fr, secp256k1::Secp256k1Affine};

use crate::{
	circuits::dynamic_sets::ecdsa_native::{
		field_value_from_pub_key, Attestation, SignedAttestation,
	},
	circuits::{PoseidonNativeHasher, PoseidonNativeSponge},
	ecdsa::native::{EcdsaVerifier, PublicKey},
	integer::native::Integer,
	params::{ecc::secp256k1::Secp256k1Params, rns::secp256k1::Secp256k1_4_68},
};

/// Opinion info of peer
pub struct Opinion<const NUM_NEIGHBOURS: usize> {
	from: PublicKey<Secp256k1Affine, Fr, 4, 68, Secp256k1_4_68, Secp256k1Params>,
	attestations: Vec<SignedAttestation>,
}

impl<const NUM_NEIGHBOURS: usize> Opinion<NUM_NEIGHBOURS> {
	/// Construct new instance
	pub fn new(
		from: PublicKey<Secp256k1Affine, Fr, 4, 68, Secp256k1_4_68, Secp256k1Params>,
		attestations: Vec<SignedAttestation>,
	) -> Self {
		Self { from, attestations }
	}

	/// Validate attestations & calculate the hash
	pub fn validate(&self, set: Vec<Fr>) -> (Fr, Vec<Fr>, Fr) {
		let from_pk = field_value_from_pub_key(&self.from);

		let pos_from = set.iter().position(|&x| x == from_pk);
		assert!(pos_from.is_some());

		let mut scores = vec![Fr::zero(); set.len()];
		let mut hashes = Vec::new();

		let default_att = SignedAttestation::default();
		let default_hasher = PoseidonNativeHasher::new([
			default_att.attestation.about,
			default_att.attestation.domain,
			default_att.attestation.value,
			default_att.attestation.message,
			Fr::zero(),
		]);
		let default_hash = default_hasher.permute()[0];
		for i in 0..NUM_NEIGHBOURS {
			let is_default_pubkey = set[i] == Fr::zero();

			let att = self.attestations[i].clone();
			let is_default_sig = att.attestation == Attestation::default();

			if is_default_pubkey || is_default_sig {
				scores[i] = Fr::default();
				hashes.push(default_hash);
			} else {
				assert!(att.attestation.about == set[i]);

				let att_hasher = PoseidonNativeHasher::new([
					att.attestation.about,
					att.attestation.domain,
					att.attestation.value,
					att.attestation.message,
					Fr::zero(),
				]);
				let att_hash = att_hasher.permute()[0];

				let sig = self.attestations[i].signature.clone();
				let msg_hash = Integer::from_n(att_hash);
				let ecdsa_verifier = EcdsaVerifier::new(sig, msg_hash, self.from.clone());
				assert!(ecdsa_verifier.verify());

				scores[i] = att.attestation.value;

				hashes.push(att_hash);
			}
		}

		let mut sponge_hasher = PoseidonNativeSponge::new();
		sponge_hasher.update(&hashes);
		let op_hash = sponge_hasher.squeeze();

		(from_pk, scores, op_hash)
	}
}
