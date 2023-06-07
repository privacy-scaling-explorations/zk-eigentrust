use halo2::halo2curves::bn256::Fr;
use secp256k1::PublicKey;

use crate::{
	circuit::PoseidonNativeSponge,
	dynamic_sets::ecdsa_native::{field_value_from_pub_key, AttestationFr, SignedAttestation},
};

/// Opinion info of peer
pub struct Opinion {
	from: PublicKey,
	attestations: Vec<SignedAttestation>,
}

impl Opinion {
	/// Construct new instance
	pub fn new(from: PublicKey, attestations: Vec<SignedAttestation>) -> Self {
		Self { from, attestations }
	}

	/// Validate attestations & calculate the hash
	pub fn validate(&self, set: Vec<Fr>) -> (Fr, Vec<Fr>, Fr) {
		let from_pk = field_value_from_pub_key(&self.from);

		println!("from_pk: {:?}", from_pk);
		println!("set: {:?}", set);

		let pos_from = set.iter().position(|&x| x == from_pk);
		assert!(pos_from.is_some());

		let mut scores = vec![Fr::zero(); set.len()];
		let mut hashes = Vec::new();
		let default_hash = AttestationFr::default().hash();
		for (i, att) in self.attestations.iter().enumerate() {
			let is_default_pubkey = set[i] == Fr::zero();

			if is_default_pubkey {
				scores[i] = Fr::default();
				hashes.push(default_hash);
			} else {
				assert!(att.attestation.about == set[i]);

				let recovered = att.recover_public_key().unwrap();
				assert!(recovered == self.from);

				scores[i] = att.attestation.value;

				let hash = att.attestation.hash();
				hashes.push(hash);
			}
		}

		let mut sponge_hasher = PoseidonNativeSponge::new();
		sponge_hasher.update(&hashes);
		let op_hash = sponge_hasher.squeeze();

		(from_pk, scores, op_hash)
	}
}
