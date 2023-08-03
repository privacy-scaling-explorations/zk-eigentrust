use std::marker::PhantomData;

use halo2::halo2curves::CurveAffine;

use crate::{
	circuits::dynamic_sets::native::{Attestation, SignedAttestation},
	circuits::HASHER_WIDTH,
	ecdsa::native::{EcdsaVerifier, PublicKey},
	integer::native::Integer,
	params::{ecc::EccParams, rns::RnsParams},
	FieldExt, Hasher, SpongeHasher,
};

/// Opinion info of peer
pub struct Opinion<
	const NUM_NEIGHBOURS: usize,
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
	EC,
	H: Hasher<N, HASHER_WIDTH>,
	SH: SpongeHasher<N>,
> where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::ScalarExt: FieldExt,
	C::Base: FieldExt,
{
	from: PublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
	attestations: Vec<SignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>>,
	domain: N,
	_h: PhantomData<(H, SH)>,
}

impl<
		const NUM_NEIGHBOURS: usize,
		C: CurveAffine,
		N: FieldExt,
		const NUM_LIMBS: usize,
		const NUM_BITS: usize,
		P,
		EC,
		H: Hasher<N, HASHER_WIDTH>,
		SH: SpongeHasher<N>,
	> Opinion<NUM_NEIGHBOURS, C, N, NUM_LIMBS, NUM_BITS, P, EC, H, SH>
where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::ScalarExt: FieldExt,
	C::Base: FieldExt,
{
	/// Construct new instance
	pub fn new(
		from: PublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
		attestations: Vec<SignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>>, domain: N,
	) -> Self {
		Self { from, attestations, domain, _h: PhantomData }
	}

	/// Validate attestations & calculate the hash
	pub fn validate(&self, set: Vec<N>) -> (N, Vec<N>, N) {
		let from_pk = self.from.to_address();

		let pos_from = set.iter().position(|&x| x == from_pk);
		assert!(pos_from.is_some());

		let mut scores = vec![N::ZERO; set.len()];
		let mut hashes = Vec::new();

		let default_att = SignedAttestation::<C, N, NUM_LIMBS, NUM_BITS, P>::default();
		let default_hasher = H::new([
			default_att.attestation.about,
			default_att.attestation.domain,
			default_att.attestation.value,
			default_att.attestation.message,
			N::ZERO,
		]);
		let default_hash = default_hasher.finalize()[0];
		for i in 0..NUM_NEIGHBOURS {
			let is_default_pubkey = set[i] == N::ZERO;

			let att = self.attestations[i].clone();
			let is_default_sig = att.attestation == Attestation::default();

			if is_default_pubkey || is_default_sig {
				scores[i] = N::ZERO;
				hashes.push(default_hash);
			} else {
				assert!(att.attestation.about == set[i]);
				assert!(att.attestation.domain == self.domain);

				let att_hasher = H::new([
					att.attestation.about,
					att.attestation.domain,
					att.attestation.value,
					att.attestation.message,
					N::ZERO,
				]);
				let att_hash = att_hasher.finalize()[0];

				let sig = self.attestations[i].signature.clone();
				let msg_hash = Integer::from_n(att_hash);
				let ecdsa_verifier = EcdsaVerifier::new(sig, msg_hash, self.from.clone());
				assert!(ecdsa_verifier.verify());

				scores[i] = att.attestation.value;

				hashes.push(att_hash);
			}
		}

		let mut sponge_hasher = SH::new();
		sponge_hasher.update(&hashes);
		let op_hash = sponge_hasher.squeeze();

		(from_pk, scores, op_hash)
	}
}
