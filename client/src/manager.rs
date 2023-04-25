//! The module for the peer related functionalities, like:
//! - Adding/removing neighbors
//! - Calculating the global trust score
//! - Calculating local scores toward neighbors for a given epoch
//! - Keeping track of neighbors scores towards us

use crate::{attestation::Attestation, error::EigenError, utils::keyset_from_raw};
use eigen_trust_circuit::{
	calculate_message_hash,
	circuit::{native, EigenTrust, PoseidonNativeHasher},
	eddsa::native::{sign, verify as verify_sig, PublicKey},
	halo2::{
		halo2curves::{
			bn256::{Bn256, Fr as Scalar, G1Affine},
			group::ff::PrimeField,
			FieldExt,
		},
		plonk::ProvingKey,
		poly::kzg::commitment::ParamsKZG,
	},
	utils::{keygen, read_json_data, read_params, to_short, write_json_data},
	verifier::gen_proof,
	Proof, ProofRaw,
};
use once_cell::sync::Lazy;
use rand::thread_rng;
use std::{
	collections::HashMap,
	sync::{Arc, Mutex},
};

/// Number of iterations to run the eigen trust algorithm
pub const NUM_ITER: usize = 10;
/// Numbers of participants
pub const NUM_NEIGHBOURS: usize = 5;
/// Initial score for each participant before the algorithms is run
pub const INITIAL_SCORE: u128 = 1000;
/// Scale for the scores to be computed inside the ZK circuit
pub const SCALE: u128 = 1000;
/// Temporary fixed set of participants
pub const FIXED_SET: [[&str; 2]; NUM_NEIGHBOURS] = [
	[
		"2L9bbXNEayuRMMbrWFynPtgkrXH1iBdfryRH9Soa8M67",
		"9rBeBVtbN2MkHDTpeAouqkMWNFJC6Bxb6bXH9jUueWaF",
	],
	[
		"ARVqgNQtnV4JTKqgajGEpuapYEnWz93S5vwRDoRYWNh8",
		"2u1LC2JmKwkzUccS9hd5yS2DUUGTuYQ8MA7y28A9SgQY",
	],
	[
		"phhPpTLWJbC4RM39Ww3e6wWvZnVkk86iNAXyA1tRAHJ",
		"93aMkAqd7AY4c3m6ij6RuBzw3F9QYhQsAMnkKF2Ck2R8",
	],
	[
		"Bp3FqLd6Man9h7xujkbYDdhyF42F2dX871SJHvo3xsnU",
		"AUUqgGTvqzPetRMQdTrQ1xHnwz2BHDxPTi85wL4WYQaK",
	],
	[
		"AKo18M6YSE1dQQuXt4HfWNrXA6dKXBVkWVghEi6827u1",
		"ArT8Kk13Heai2UPbMbrqs3RuVm4XXFN2pVHttUnKpDoV",
	],
];
/// Public key hashes of all participants
pub const PUBLIC_KEYS: [&str; NUM_NEIGHBOURS] = [
	"92tZdMN2SjXbT9byaHHt7hDDNXUphjwRt5UB3LDbgSmR",
	"8uFaYMkkACmnUBRZyA9JbWVjP1KN1BA53wcfKHhGE3kg",
	"DqVjJk7pBjnLXGVsCdD8SVQZLF3SZyypCB6SBJobwUMc",
	"tbXeMMQDSs3XuKUJuzJyU2jTzr66iWtHaMb2eKiqUFM",
	"Gz4dAnn3ex5Pq2vZQyJ94EqDdxpFaY74GJDFuuALvD6b",
];

/// The peer struct.
pub struct Manager {
	attestations: HashMap<Scalar, Attestation>,
	params: ParamsKZG<Bn256>,
	proving_key: ProvingKey<G1Affine>,
}

impl Manager {
	/// Creates a new peer.
	pub fn new(params: ParamsKZG<Bn256>, pk: ProvingKey<G1Affine>) -> Self {
		Self { attestations: HashMap::new(), params, proving_key: pk }
	}

	/// Add a new attestation into the cache, by first calculating the hash of
	/// the proving key
	pub fn add_attestation(&mut self, att: Attestation) -> Result<(), EigenError> {
		let group = PUBLIC_KEYS
			.map(|x| bs58::decode(x).into_vec().unwrap())
			.map(|x| to_short(&x))
			.map(|x| Scalar::from_repr(x).unwrap());

		let pk_hashes: Vec<Scalar> = att
			.neighbours
			.iter()
			.map(|pk| {
				let mut inps = [Scalar::zero(); 5];
				inps[0] = pk.0.x;
				inps[1] = pk.0.y;

				PoseidonNativeHasher::new(inps).permute()[0]
			})
			.collect();

		if group.as_ref() != pk_hashes {
			return Err(EigenError::InvalidAttestation);
		}

		let mut pk_hash_inp = [Scalar::zero(); 5];
		pk_hash_inp[0] = att.pk.0.x;
		pk_hash_inp[1] = att.pk.0.y;
		let res = PoseidonNativeHasher::new(pk_hash_inp).permute()[0];

		if !group.contains(&res) {
			return Err(EigenError::InvalidAttestation);
		}

		let (_, message_hash) = calculate_message_hash::<NUM_NEIGHBOURS, 1>(
			att.neighbours.clone(),
			vec![att.scores.clone()],
		);

		if !verify_sig(&att.sig, &att.pk, message_hash[0]) {
			return Err(EigenError::InvalidAttestation);
		}

		self.attestations.insert(res, att);

		Ok(())
	}

	/// Adds multiple attestations
	pub fn add_attestations(&mut self, atts: Vec<Attestation>) -> Result<(), EigenError> {
		for att in atts {
			self.add_attestation(att)?;
		}

		Ok(())
	}

	/// Get the attestation cached under the hash of the public key
	pub fn get_attestation(&self, pk: &PublicKey) -> Result<&Attestation, EigenError> {
		let pk_hash_inp = [pk.0.x, pk.0.y, Scalar::zero(), Scalar::zero(), Scalar::zero()];
		let res = PoseidonNativeHasher::new(pk_hash_inp).permute()[0];
		self.attestations.get(&res).ok_or(EigenError::AttestationNotFound)
	}

	/// Generate initial attestations, since the circuit requires scores from
	/// all participants in the fixed set
	pub fn generate_initial_attestations(&mut self) {
		let (sks, pks) = keyset_from_raw(FIXED_SET);

		let score = Scalar::from_u128(INITIAL_SCORE / NUM_NEIGHBOURS as u128);
		let scores = vec![vec![score; NUM_NEIGHBOURS]; NUM_NEIGHBOURS];

		const N: usize = NUM_NEIGHBOURS;
		let (_, messages) = calculate_message_hash::<N, N>(pks.clone(), scores.clone());

		for (((sk, pk), msg), scs) in sks.into_iter().zip(pks.clone()).zip(messages).zip(scores) {
			let sig = sign(&sk, &pk, msg);

			let pk_hash_inp = [pk.0.x, pk.0.y, Scalar::zero(), Scalar::zero(), Scalar::zero()];
			let pk_hash = PoseidonNativeHasher::new(pk_hash_inp).permute()[0];

			let att = Attestation::new(sig, pk, pks.clone(), scs);
			self.attestations.insert(pk_hash, att);
		}
	}

	/// Calculate the scores for the given epoch, and cache the ZK proof of them
	pub fn calculate_proofs(&mut self) -> Result<(), EigenError> {
		let (_, pks) = keyset_from_raw(FIXED_SET);

		let pk_hashes: Vec<Scalar> = pks
			.iter()
			.map(|pk| {
				let pk_hash_inp = [pk.0.x, pk.0.y, Scalar::zero(), Scalar::zero(), Scalar::zero()];

				PoseidonNativeHasher::new(pk_hash_inp).permute()[0]
			})
			.collect();

		let mut ops = Vec::new();
		let mut sigs = Vec::new();
		for pk_hash in pk_hashes {
			let att = self.attestations.get(&pk_hash).unwrap();
			ops.push(att.scores.to_vec());
			sigs.push(att.sig.clone());
		}

		let et = EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::new(
			pks,
			sigs,
			ops.clone(),
		);
		let init_score = vec![Scalar::from_u128(INITIAL_SCORE); NUM_NEIGHBOURS];
		let pub_ins = native::<Scalar, NUM_NEIGHBOURS, NUM_ITER, SCALE>(init_score, ops);

		let proof_bytes = gen_proof(&self.params, &self.proving_key, et, vec![pub_ins.clone()]);

		let proof = Proof { pub_ins, proof: proof_bytes };

		write_json_data(ProofRaw::from(proof), "et-proof").unwrap();

		Ok(())
	}

	/// Get the last generated proof
	pub fn get_last_proof() -> Result<Proof, EigenError> {
		match read_json_data::<ProofRaw>("et-proof") {
			Ok(proof_raw) => Ok(Proof::from(proof_raw)),
			Err(_) => Err(EigenError::ProofNotFound),
		}
	}
}

/// Singleton `Manager` instance
pub static MANAGER_STORE: Lazy<Arc<Mutex<Manager>>> = Lazy::new(|| {
	let k = 14;
	let params = read_params(k);
	let rng = &mut thread_rng();

	let et = EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::random(rng);
	let proving_key = keygen(&params, et).unwrap();

	Arc::new(Mutex::new(Manager::new(params, proving_key)))
});

#[cfg(test)]
mod test {
	use super::*;
	use eigen_trust_circuit::{
		halo2::poly::commitment::ParamsProver,
		utils::keygen,
		verifier::{evm_verify, gen_evm_verifier},
	};
	use rand::thread_rng;

	#[test]
	fn should_calculate_proof() {
		let mut rng = thread_rng();
		let params = ParamsKZG::new(14);
		let random_circuit =
			EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::random(&mut rng);
		let proving_key = keygen(&params, random_circuit).unwrap();
		let mut manager = Manager::new(params.clone(), proving_key.clone());

		manager.generate_initial_attestations();
		manager.calculate_proofs().unwrap();

		let proof = Manager::get_last_proof().unwrap();
		let scores = [Scalar::from_u128(INITIAL_SCORE); NUM_NEIGHBOURS];
		assert_eq!(proof.pub_ins, scores);

		let verifier_code = gen_evm_verifier(&params, proving_key.get_vk(), vec![NUM_NEIGHBOURS]);
		evm_verify(verifier_code, vec![proof.pub_ins], proof.proof);
	}
}
