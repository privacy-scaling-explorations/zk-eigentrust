/// Native version of Opinion
pub mod native;

use crate::{
	ecc::generic::{AssignedAux, AssignedEcPoint},
	ecdsa::{AssignedPublicKey, AssignedSignature, EcdsaChipset, EcdsaConfig},
	gadgets::{
		main::{IsEqualChipset, IsZeroChipset, MainConfig, MulAddChipset, SelectChipset},
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
pub struct OpinionConfig<F: FieldExt, H, S>
where
	H: HasherChipset<F, WIDTH>,
	S: SpongeHasherChipset<F>,
{
	ecdsa: EcdsaConfig,
	main: MainConfig,
	set: SetConfig,
	hasher: H::Config,
	sponge: S::Config,
}

impl<F: FieldExt, H, S> OpinionConfig<F, H, S>
where
	H: HasherChipset<F, WIDTH>,
	S: SpongeHasherChipset<F>,
{
	/// Construct a new config
	pub fn new(
		ecdsa: EcdsaConfig, main: MainConfig, set: SetConfig, hasher: H::Config, sponge: S::Config,
	) -> Self {
		Self { ecdsa, main, set, hasher, sponge }
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
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::Scalar, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
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
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::Scalar, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
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

	/// Create a new chip.
	pub fn left_shifters(
		common: &CommonConfig, mut layouter: impl Layouter<N>,
	) -> [AssignedCell<N, N>; NUM_LIMBS] {
		let left_shifters_native = P::left_shifters();
		let mut left_shifters = [(); NUM_LIMBS].map(|_| None);
		layouter.assign_region(
			|| "assign_left_shifters",
			|region: Region<'_, N>| {
				let mut ctx = RegionCtx::new(region, 0);
				for i in 0..NUM_LIMBS {
					left_shifters[i] =
						Some(ctx.assign_fixed(common.fixed[i], left_shifters_native[i])?);
				}
				Ok(())
			},
		);
		left_shifters.map(|x| x.unwrap())
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
	type Config = OpinionConfig<N, H, S>;
	type Output = (
		AssignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P>,
		Vec<AssignedCell<N, N>>,
		AssignedCell<N, N>,
	);

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<N>,
	) -> Result<Self::Output, Error> {
		// TODO: Checks given set for the public key

		let (zero, one) = layouter.assign_region(
			|| "assign_zero",
			|region: Region<'_, N>| {
				let mut ctx = RegionCtx::new(region, 0);
				let zero = ctx.assign_from_constant(common.advice[0], N::ZERO)?;
				let one = ctx.assign_from_constant(common.advice[1], N::ONE)?;

				Ok((zero, one))
			},
		)?;

		let mut scores = vec![zero.clone(); self.set.len()];
		let mut hashes = Vec::new();

		// Hashing default values for default attestation
		let hash = H::new([zero.clone(), zero.clone(), zero.clone(), zero.clone(), zero.clone()]);
		let default_hash = hash.finalize(
			common,
			&config.hasher,
			layouter.namespace(|| "default_hash"),
		)?;

		for i in 0..NUM_NEIGHBOURS {
			// Checking pubkey and attestation values if they are default or not (default is zero)
			let is_zero_chip = IsZeroChipset::new(self.set[i].clone());
			let is_default_pubkey = is_zero_chip.synthesize(
				common,
				&config.main,
				layouter.namespace(|| "is_default_pubkey"),
			)?;

			let att = self.attestations[i].clone();
			let is_zero_chip = IsZeroChipset::new(att.attestation.about.clone());
			let att_about = is_zero_chip.synthesize(
				common,
				&config.main,
				layouter.namespace(|| "att_about"),
			)?;

			let is_zero_chip = IsZeroChipset::new(att.attestation.domain.clone());
			let att_domain = is_zero_chip.synthesize(
				common,
				&config.main,
				layouter.namespace(|| "att_domain"),
			)?;

			let is_zero_chip = IsZeroChipset::new(att.attestation.value.clone());
			let att_value = is_zero_chip.synthesize(
				common,
				&config.main,
				layouter.namespace(|| "att_value"),
			)?;

			let is_zero_chip = IsZeroChipset::new(att.attestation.message.clone());
			let att_message = is_zero_chip.synthesize(
				common,
				&config.main,
				layouter.namespace(|| "att_message"),
			)?;

			let multi_and_check =
				vec![is_default_pubkey, att_about, att_domain, att_message, att_value];

			// Checks if there is a zero value. If there is a zero value in the set that means one of the variable is not default.
			// Basically, instead of doing 3 AND operation we did one set check
			let set_chip = SetChipset::new(multi_and_check, zero.clone());
			let is_default_values_zero = set_chip.synthesize(
				common,
				&config.set,
				layouter.namespace(|| "set_check_zero"),
			)?;

			// Checks equality of the attestation about and set index
			let is_equal_chip =
				IsEqualChipset::new(att.attestation.about.clone(), self.set[i].clone());
			let equality_check_set_about = is_equal_chip.synthesize(
				common,
				&config.main,
				layouter.namespace(|| "is_equal_chipset_set"),
			)?;

			let hash = H::new([
				att.attestation.about,
				att.attestation.domain,
				att.attestation.value.clone(),
				att.attestation.message.clone(),
				zero.clone(),
			]);
			let att_hash =
				hash.finalize(common, &config.hasher, layouter.namespace(|| "att_hash"))?;

			let signature = self.attestations[i].signature.clone();

			let left_shifters = Self::left_shifters(common, layouter.namespace(|| "left_shifters"));
			let mut compose_msg = zero.clone();
			for i in 0..NUM_LIMBS {
				let muladd_chipset =
					MulAddChipset::new(self.msg_hash[i].limbs[i], left_shifters[i], compose_msg);
				compose_msg = muladd_chipset.synthesize(
					common,
					&config.main,
					layouter.namespace(|| "mul_add"),
				)?;
			}

			//TODO: Constraint equality for the msg_hash from hasher and constructor
			// Constraint equality for the set and att.about
			layouter.assign_region(
				|| "constraint equality",
				|region: Region<'_, N>| {
					let mut ctx = RegionCtx::new(region, 0);
					let val = P::compose(self.msg_hash[i].integer.limbs);
					let msg_hash = ctx.assign_advice(common.advice[0], Value::known(val))?;
					ctx.constrain_equal(att_hash[0], compose_msg);
					ctx.constrain_equal(equality_check_set_about, one);
					Ok(())
				},
			)?;

			let chip = EcdsaChipset::new(
				self.public_key.clone(),
				self.g_as_ecpoint.clone(),
				signature.clone(),
				self.msg_hash[i].clone(),
				self.s_inv.clone(),
				self.aux.clone(),
			);
			chip.synthesize(common, &config.ecdsa, layouter.namespace(|| "ecdsa_verify"))?;

			scores[i] = att.attestation.value;

			// Select chip for if case
			let select_chip = SelectChipset::new(
				is_default_values_zero,
				default_hash[0].clone(),
				att_hash[0].clone(),
			);
			let selected_value = select_chip.synthesize(
				common,
				&config.main,
				layouter.namespace(|| "select chipset"),
			)?;

			hashes.push(selected_value);
		}

		let mut sponge = S::init(common, layouter.namespace(|| "sponge"))?;
		sponge.update(&hashes);
		let op_hash = sponge.squeeze(common, &config.sponge, layouter.namespace(|| "squeeze!"))?;

		Ok((self.public_key, scores, op_hash))
	}
}
