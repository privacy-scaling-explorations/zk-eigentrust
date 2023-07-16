/// Native version of Opinion
pub mod native;

use crate::{
	ecc::generic::{AssignedAux, AssignedEcPoint},
	ecdsa::{AssignedPublicKey, AssignedSignature, EcdsaChipset, EcdsaConfig},
	gadgets::{
		main::{IsZeroChipset, MainConfig, SelectChipset},
		set::{SetChipset, SetConfig},
	},
	integer::AssignedInteger,
	params::{ecc::EccParams, rns::RnsParams},
	Chipset, CommonConfig, FieldExt, HasherChipset, RegionCtx, SpongeHasherChipset,
};
use halo2::{
	circuit::{AssignedCell, Layouter, Region, Value},
	halo2curves::CurveAffine,
	plonk::Error,
};
use std::marker::PhantomData;

const WIDTH: usize = 5;

/// Assigned Attestation structure.
#[derive(Debug, Clone)]
pub struct AssignedAttestation<F: FieldExt> {
	/// Ethereum address of peer being rated
	pub about: AssignedCell<F, F>,
	/// Unique identifier for the action being rated
	pub domain: AssignedCell<F, F>,
	/// Given rating for the action
	pub value: AssignedCell<F, F>,
	/// Optional field for attaching additional information to the attestation
	pub message: AssignedCell<F, F>,
}

impl<F: FieldExt> AssignedAttestation<F> {
	/// Creates a new AssignedAttestation
	pub fn new(
		about: AssignedCell<F, F>, domain: AssignedCell<F, F>, value: AssignedCell<F, F>,
		message: AssignedCell<F, F>,
	) -> Self {
		Self { about, domain, value, message }
	}
}

/// SignedAssignedAttestation structure.
#[derive(Debug, Clone)]
pub struct SignedAssignedAttestation<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	// Attestation
	attestation: AssignedAttestation<N>,
	// Signature
	signature: AssignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	SignedAssignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	/// Creates a new SignedAssignedAttestation
	pub fn new(
		attestation: AssignedAttestation<N>,
		signature: AssignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { attestation, signature }
	}
}

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct OpinionConfig<F: FieldExt, H>
where
	H: HasherChipset<F, WIDTH>,
{
	ecdsa: EcdsaConfig,
	main: MainConfig,
	set: SetConfig,
	select: SelectChipset<F>,
	hasher: H::Config,
}

impl<F: FieldExt, H> OpinionConfig<F, H>
where
	H: HasherChipset<F, WIDTH>,
{
	/// Construct a new config
	pub fn new(
		ecdsa: EcdsaConfig, main: MainConfig, set: SetConfig, select: SelectChipset<F>,
		hasher: H::Config,
	) -> Self {
		Self { ecdsa, main, set, select, hasher }
	}
}

/// Constructs a chip for the circuit.
#[derive(Clone)]
pub struct OpinionChipset<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	const NUM_NEIGHBOURS: usize,
	H,
	S,
	P,
	EC,
> where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
	H: HasherChipset<N, WIDTH>,
	S: SpongeHasherChipset<N>,
{
	// Attestations
	attestations: Vec<SignedAssignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>>,
	// Public key
	public_key: AssignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P>,
	// Set
	set: Vec<AssignedCell<N, N>>,
	// msg_hash as AssignedInteger
	msg_hash: Vec<AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>>,
	// Generator as EC point
	g_as_ecpoint: AssignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
	// Signature Inverse
	s_inv: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	// Aux for to_add and to_sub
	aux: AssignedAux<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
	/// Constructs a phantom data for the hasher.
	_hasher: PhantomData<(H, S, EC)>,
}

impl<
		C: CurveAffine,
		N: FieldExt,
		const NUM_LIMBS: usize,
		const NUM_BITS: usize,
		const NUM_NEIGHBOURS: usize,
		H,
		S,
		P,
		EC,
	> OpinionChipset<C, N, NUM_LIMBS, NUM_BITS, NUM_NEIGHBOURS, H, S, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
	H: HasherChipset<N, WIDTH>,
	S: SpongeHasherChipset<N>,
{
	/// Create a new chip.
	pub fn new(
		attestations: Vec<SignedAssignedAttestation<C, N, NUM_LIMBS, NUM_BITS, P>>,
		public_key: AssignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P>, set: Vec<AssignedCell<N, N>>,
		msg_hash: Vec<AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>>,
		g_as_ecpoint: AssignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
		s_inv: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
		aux: AssignedAux<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
	) -> Self {
		OpinionChipset {
			attestations,
			public_key,
			set,
			msg_hash,
			g_as_ecpoint,
			s_inv,
			aux,
			_hasher: PhantomData,
		}
	}
}

impl<
		C: CurveAffine,
		N: FieldExt,
		const NUM_LIMBS: usize,
		const NUM_BITS: usize,
		const NUM_NEIGHBOURS: usize,
		H,
		S,
		P,
		EC,
	> Chipset<N> for OpinionChipset<C, N, NUM_LIMBS, NUM_BITS, NUM_NEIGHBOURS, H, S, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
	H: HasherChipset<N, WIDTH>,
	S: SpongeHasherChipset<N>,
{
	type Config = OpinionConfig<N, H>;
	type Output = ();

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<N>,
	) -> Result<Self::Output, Error> {
		let zero = layouter.assign_region(
			|| "assign_zero",
			|region: Region<'_, N>| {
				let mut ctx = RegionCtx::new(region, 0);
				ctx.assign_from_constant(common.advice[0], N::ZERO)
			},
		)?;

		let mut scores = vec![zero.clone(); self.set.len()];
		let mut hashes = Vec::new();

		// Hashing default values for default attestation
		let hash = H::new([zero.clone(), zero.clone(), zero.clone(), zero.clone(), zero.clone()]);
		let default_hash = hash.finalize(
			&common,
			&config.hasher,
			layouter.namespace(|| "default_hash"),
		)?;

		for i in 0..NUM_NEIGHBOURS {
			// Checking pubkey and attestation values if they are default or not (default is zero)
			let is_zero_chip = IsZeroChipset::new(self.set[i].clone());
			let is_default_pubkey = is_zero_chip.synthesize(
				&common,
				&config.main,
				layouter.namespace(|| "is_default_pubkey"),
			)?;

			let att = self.attestations[i].clone();
			let is_zero_chip = IsZeroChipset::new(att.attestation.about.clone());
			let att_about = is_zero_chip.synthesize(
				&common,
				&config.main,
				layouter.namespace(|| "att_about"),
			)?;

			let is_zero_chip = IsZeroChipset::new(att.attestation.domain.clone());
			let att_domain = is_zero_chip.synthesize(
				&common,
				&config.main,
				layouter.namespace(|| "att_domain"),
			)?;

			let is_zero_chip = IsZeroChipset::new(att.attestation.value.clone());
			let att_value = is_zero_chip.synthesize(
				&common,
				&config.main,
				layouter.namespace(|| "att_value"),
			)?;

			let is_zero_chip = IsZeroChipset::new(att.attestation.message.clone());
			let att_message = is_zero_chip.synthesize(
				&common,
				&config.main,
				layouter.namespace(|| "att_message"),
			)?;

			let multi_and_check =
				vec![is_default_pubkey, att_about, att_domain, att_message, att_value];

			// Checks if there is a zero value. If there is a zero value in the set that means one of the variable is not default.
			// Basically, instead of doing 3 AND operation we did one set check
			let set_chip = SetChipset::new(multi_and_check, zero.clone());
			let is_default_values_zero = set_chip.synthesize(
				&common,
				&config.set,
				layouter.namespace(|| "set_check_zero"),
			)?;

			//assert!(att.attestation.about == self.set[i]);

			let hash = H::new([
				att.attestation.about,
				att.attestation.domain,
				att.attestation.value.clone(),
				att.attestation.message.clone(),
				zero.clone(),
			]);
			let att_hash =
				hash.finalize(&common, &config.hasher, layouter.namespace(|| "att_hash"))?;

			let signature = self.attestations[i].signature.clone();

			// Constraint equality for the msg_hash from hasher and constructor
			//layouter.assign_region(
			//	|| "constraint equality",
			//	|region: Region<'_, N>| {
			//		let mut ctx = RegionCtx::new(region, 0);
			//		let msg_hash = ctx.assign_advice(
			//			common.advice[0],
			//			Value::known(P::compose(self.msg_hash[i].integer.limbs)),
			//		)?;
			//		ctx.constrain_equal(att_hash[0], msg_hash)
			//	},
			//)?;

			let chip = EcdsaChipset::new(
				self.public_key.clone(),
				self.g_as_ecpoint.clone(),
				signature.clone(),
				self.msg_hash[i].clone(),
				self.s_inv.clone(),
				self.aux.clone(),
			);
			chip.synthesize(
				&common,
				&config.ecdsa,
				layouter.namespace(|| "ecdsa_verify"),
			)?;

			scores[i] = att.attestation.value;

			// Select chip for if case
			let select_chip = SelectChipset::new(
				is_default_values_zero,
				default_hash[0].clone(),
				att_hash[0].clone(),
			);
			let selected_value = select_chip.synthesize(
				&common,
				&config.main,
				layouter.namespace(|| "select chipset"),
			)?;

			hashes.push(selected_value);
		}

		let mut sponge = S::init(common, layouter.namespace(|| "sponge"))?;
		sponge.update(&hashes);
		let op_hash = sponge.squeeze(common, config, layouter.namespace(|| "squeeze!"))?;

		Ok(())
	}
}
