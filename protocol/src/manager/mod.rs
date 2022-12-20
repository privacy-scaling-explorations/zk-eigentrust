//! The module for the peer related functionalities, like:
//! - Adding/removing neighbors
//! - Calculating the global trust score
//! - Calculating local scores toward neighbors for a given epoch
//! - Keeping track of neighbors scores towards us

/// Attestation implementation
pub mod attestation;

use crate::{
	epoch::Epoch,
	error::EigenError,
	utils::{scalar_from_bs58, to_wide_bytes},
};
use attestation::Attestation;
use bs58::decode::Error as Bs58Error;
use eigen_trust_circuit::{
	circuit::{native, EigenTrust, PoseidonNativeHasher, PoseidonNativeSponge},
	eddsa::native::{PublicKey, SecretKey, Signature},
	halo2wrong::{
		curves::{
			bn256::{Bn256, Fr as Scalar, G1Affine},
			group::ff::PrimeField,
			FieldExt,
		},
		halo2::{
			plonk::{ProvingKey, VerifyingKey},
			poly::kzg::commitment::ParamsKZG,
		},
	},
	params::poseidon_bn254_5x5::Params,
	poseidon::native::Poseidon,
	utils::{prove, verify},
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const NUM_ITER: usize = 10;
pub const NUM_NEIGHBOURS: usize = 5;
pub const INITIAL_SCORE: u128 = 1000;
pub const SCALE: u128 = 1000;
pub const FIXED_SET: [[&str; 2]; NUM_NEIGHBOURS] = [
	[
		"AF4yAqwCPzpBcit4FtTrHso4BBR9onk7qS9Q1SWSLSaV",
		"52RwQpZ9kUDsNi9R8f5FMD27pqyTPB39hQKYeH7fH99P",
	],
	[
		"7VoQFngkSo36s5yzZtnjtZ5SLe1VGukCZdb5Uc9tSDNC",
		"HhfwhxzwKvS8UGVvfnyJUiA1uL1VhXXfqFWh4BtEM9zx",
	],
	[
		"3wEvtEFktXUBHZHPPmLkDh7oqFLnjTPep1EJ2eBqLtcX",
		"5vnn3M32KhDE9qsvWGbSy8H59y6Kf64TKmqLeRxKwn6t",
	],
	[
		"AccKg5pXVG5o968qj5QtgPZpgC8Y8NLG9woUZNuZRYdG",
		"3BGPsex45AHQHuJfkfWkMfKHcwNjYcXhC3foH77kurPX",
	],
	[
		"8hz2emqxU7CfxWv8cJLFGR1nE4B5QDsfNE4LykE6ihKB",
		"2hfQezShegBrascTTkbCjPzbLZSq6KADnkZbBjQ2uaih",
	],
];

pub struct Proof {
	pub_ins: [Scalar; NUM_NEIGHBOURS],
	proof: Vec<u8>,
}

/// The peer struct.
pub struct Manager {
	pub(crate) cached_proofs: HashMap<Epoch, Proof>,
	pub(crate) attestations: HashMap<Scalar, Attestation>,
	params: ParamsKZG<Bn256>,
	proving_key: ProvingKey<G1Affine>,
}

impl Manager {
	/// Creates a new peer.
	pub fn new(params: ParamsKZG<Bn256>, pk: ProvingKey<G1Affine>) -> Self {
		Self {
			cached_proofs: HashMap::new(),
			attestations: HashMap::new(),
			params,
			proving_key: pk,
		}
	}

	pub fn add_attestation(&mut self, sig: Attestation) {
		let pk_hash_inp = [sig.pk.0.x, sig.pk.0.y, Scalar::zero(), Scalar::zero(), Scalar::zero()];
		let res = PoseidonNativeHasher::new(pk_hash_inp).permute()[0];
		self.attestations.insert(res, sig);
	}

	pub fn get_attestation(&self, pk: &PublicKey) -> Result<&Attestation, EigenError> {
		let pk_hash_inp = [pk.0.x, pk.0.y, Scalar::zero(), Scalar::zero(), Scalar::zero()];
		let res = PoseidonNativeHasher::new(pk_hash_inp).permute()[0];
		self.attestations.get(&res).ok_or(EigenError::AttestationNotFound)
	}

	pub fn calculate_proofs(&mut self, epoch: Epoch) -> Result<(), EigenError> {
		let mut pks: [Option<PublicKey>; NUM_NEIGHBOURS] = [(); NUM_NEIGHBOURS].map(|_| None);
		let mut pk_hashes: [Option<Scalar>; NUM_NEIGHBOURS] = [None; NUM_NEIGHBOURS];
		for (i, sk_raw) in FIXED_SET.iter().enumerate() {
			let sk0_raw = bs58::decode(sk_raw[0]).into_vec().unwrap();
			let sk1_raw = bs58::decode(sk_raw[1]).into_vec().unwrap();

			let mut sk0_bytes: [u8; 32] = [0; 32];
			sk0_bytes.copy_from_slice(&sk0_raw);
			let mut sk1_bytes: [u8; 32] = [0; 32];
			sk1_bytes.copy_from_slice(&sk1_raw);

			let sk = SecretKey::from_raw([sk0_bytes, sk1_bytes]);
			let pk = sk.public();
			let pk_hash_inp = [pk.0.x, pk.0.y, Scalar::zero(), Scalar::zero(), Scalar::zero()];
			let pk_hash = PoseidonNativeHasher::new(pk_hash_inp).permute()[0];
			println!(
				"pk_hash: {}",
				bs58::encode(pk_hash.to_bytes()).into_string()
			);
			// assert!(self.attestations.contains_key(&pk_hash));
			pks[i] = Some(pk);
			pk_hashes[i] = Some(pk_hash);
		}

		let pks = pks.map(|pk| pk.unwrap());
		let pk_hashes = pk_hashes.map(|pk_h| pk_h.unwrap());

		let pks_x = pks.clone().map(|pk| pk.0.x);
		let pks_y = pks.clone().map(|pk| pk.0.y);
		let mut pk_sponge = PoseidonNativeSponge::new();
		pk_sponge.update(&pks_x);
		pk_sponge.update(&pks_y);
		let pks_hash = pk_sponge.squeeze();

		let mut ops = [[Scalar::zero(); NUM_NEIGHBOURS]; NUM_NEIGHBOURS];
		let mut sigs = [(); NUM_NEIGHBOURS].map(|_| None);
		let mut messages = [Scalar::zero(); NUM_NEIGHBOURS];

		for (i, pk_hash) in pk_hashes.iter().enumerate() {
			let att = self.attestations.get(&pk_hash).unwrap();
			let scores = att.scores.map(|x| x.unwrap_or(Scalar::zero()));

			let mut scores_sponge = PoseidonNativeSponge::new();
			scores_sponge.update(&scores);
			let scores_hash = scores_sponge.squeeze();

			let final_hash_input =
				[pks_hash, scores_hash, Scalar::zero(), Scalar::zero(), Scalar::zero()];
			let final_hash = PoseidonNativeHasher::new(final_hash_input).permute()[0];

			ops[i] = scores;
			sigs[i] = Some(att.sig.clone());
			messages[i] = final_hash;
		}

		let sigs = sigs.map(|s| s.unwrap());

		let mut rng = thread_rng();
		let et = EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::new(
			pks, sigs, ops, messages,
		);
		let init_score = [(); NUM_NEIGHBOURS].map(|_| Scalar::from_u128(INITIAL_SCORE));
		let pub_ins = native::<Scalar, NUM_NEIGHBOURS, NUM_ITER, SCALE>(init_score, ops);

		let proof_bytes = prove(&self.params, et, &[&pub_ins], &self.proving_key, &mut rng)
			.map_err(|_| EigenError::ProvingError)?;

		// Sanity check
		let proof_res = verify(
			&self.params,
			&[&pub_ins],
			&proof_bytes,
			self.proving_key.get_vk(),
		)
		.map_err(|e| EigenError::VerificationError)?;
		assert!(proof_res);

		let proof = Proof { pub_ins, proof: proof_bytes };
		self.cached_proofs.insert(epoch, proof);

		Ok(())
	}
}

#[cfg(test)]
mod test {

	#[test]
	fn should_calculate_proof() {}
}
