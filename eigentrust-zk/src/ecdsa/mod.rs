/// Native version of Ecdsa
pub mod native;

use self::native::{PublicKey, Signature};
use crate::ecc::generic::{
	AssignedAux, AssignedEcPoint, AuxAssigner, EccAddChipset, PointAssigner, UnassignedEcPoint,
};
use crate::ecc::{AuxConfig, EccAddConfig};
use crate::integer::native::Integer;
use crate::integer::{IntegerAssigner, UnassignedInteger};
use crate::params::ecc::EccParams;
use crate::{
	ecc::{generic::EccMulChipset, EccMulConfig},
	integer::{AssignedInteger, IntegerMulChip},
	params::rns::RnsParams,
	Chipset, CommonConfig, FieldExt,
};
use crate::{Chip, RegionCtx, UnassignedValue};
use halo2::circuit::{Region, Value};
use halo2::{
	circuit::Layouter,
	halo2curves::CurveAffine,
	plonk::{Error, Selector},
};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
/// Unassigned signature structure
pub struct UnassignedSignature<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::ScalarExt: FieldExt,
{
	pub(crate) r: UnassignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	pub(crate) s: UnassignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	UnassignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::ScalarExt: FieldExt,
{
	/// Constructor for unassigned signature
	pub fn new(sig: Signature<C, N, NUM_LIMBS, NUM_BITS, P>) -> Self {
		Self {
			r: UnassignedInteger::new(
				sig.r.clone(),
				Value::known(P::compose(sig.r.limbs)),
				sig.r.limbs.map(|x| Value::known(x)),
			),
			s: UnassignedInteger::new(
				sig.s.clone(),
				Value::known(P::compose(sig.s.limbs)),
				sig.s.limbs.map(|x| Value::known(x)),
			),
		}
	}
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	From<Signature<C, N, NUM_LIMBS, NUM_BITS, P>> for UnassignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::ScalarExt: FieldExt,
{
	fn from(sig: Signature<C, N, NUM_LIMBS, NUM_BITS, P>) -> Self {
		Self { r: UnassignedInteger::from(sig.r), s: UnassignedInteger::from(sig.s) }
	}
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> UnassignedValue
	for UnassignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::ScalarExt: FieldExt,
{
	fn without_witnesses() -> Self {
		Self {
			r: UnassignedInteger::without_witnesses(),
			s: UnassignedInteger::without_witnesses(),
		}
	}
}

#[derive(Clone, Debug)]
/// Assigned signature structure
pub struct AssignedSignature<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::ScalarExt: FieldExt,
{
	r: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	s: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	AssignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::ScalarExt: FieldExt,
{
	/// Creates a new Assigned Signature object
	pub fn new(
		r: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
		s: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { r, s }
	}
}

/// Signature assigner chipset
pub struct SignatureAssigner<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::ScalarExt: FieldExt,
{
	sig: UnassignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	SignatureAssigner<C, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::ScalarExt: FieldExt,
{
	/// Constructor for Signature assigner
	pub fn new(sig: UnassignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>) -> Self {
		Self { sig }
	}
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Chipset<N>
	for SignatureAssigner<C, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::ScalarExt: FieldExt,
{
	type Config = ();
	type Output = AssignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>;

	fn synthesize(
		self, common: &CommonConfig, _: &Self::Config, mut layouter: impl Layouter<N>,
	) -> Result<Self::Output, Error> {
		let signature_r_assigner = IntegerAssigner::new(self.sig.r);
		let signature_r = signature_r_assigner.synthesize(
			common,
			&(),
			layouter.namespace(|| "signature_r assigner"),
		)?;

		let signature_s_assigner = IntegerAssigner::new(self.sig.s);
		let signature_s = signature_s_assigner.synthesize(
			common,
			&(),
			layouter.namespace(|| "signature_s assigner"),
		)?;

		Ok(AssignedSignature::new(signature_r, signature_s))
	}
}

/// Unassigned Public Key structure
#[derive(Clone, Debug)]
pub struct UnassignedPublicKey<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
	EC,
>(pub(crate) UnassignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>)
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt;

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
	UnassignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
	EC: EccParams<C>,
{
	/// Creates a new Unassigned Public Key object
	pub fn new(pk: PublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>) -> Self {
		let x = UnassignedInteger::new(
			pk.0.x.clone(),
			Value::known(<P as RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS>>::compose(
				pk.0.x.limbs,
			)),
			pk.0.x.limbs.map(|x| Value::known(x)),
		);
		let y = UnassignedInteger::new(
			pk.0.y.clone(),
			Value::known(<P as RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS>>::compose(
				pk.0.y.limbs,
			)),
			pk.0.y.limbs.map(|x| Value::known(x)),
		);
		let p = UnassignedEcPoint::new(x, y);
		Self(p)
	}
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
	UnassignedValue for UnassignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
	EC: EccParams<C>,
{
	fn without_witnesses() -> Self {
		Self(UnassignedEcPoint::without_witnesses())
	}
}

#[derive(Clone, Debug)]
/// Assigned public key structure
pub struct AssignedPublicKey<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
>(AssignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P>)
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt;

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	AssignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
{
	/// Constructor for assigned public key
	pub fn new(p: AssignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P>) -> Self {
		Self(p)
	}
}

/// Public Key Assigner structure
pub struct PublicKeyAssigner<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
	EC,
>(UnassignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>)
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt;

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
	PublicKeyAssigner<C, N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
{
	/// Creates a new public key assigner object
	pub fn new(p: UnassignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>) -> Self {
		Self(p)
	}
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC> Chipset<N>
	for PublicKeyAssigner<C, N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Config = ();
	type Output = AssignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P>;

	fn synthesize(
		self, common: &CommonConfig, _: &Self::Config, mut layouter: impl Layouter<N>,
	) -> Result<Self::Output, Error> {
		let public_key_assigner = PointAssigner::new(self.0 .0);
		let public_key = public_key_assigner.synthesize(
			common,
			&(),
			layouter.namespace(|| "public_key assigner"),
		)?;

		let pk = AssignedPublicKey::new(public_key);
		Ok(pk)
	}
}

#[derive(Clone, Debug)]
/// Configuration structure for the Ecdsa
pub struct EcdsaConfig {
	// ECC scalar multiplication configuration
	ecc_mul_scalar: EccMulConfig,
	// ECC addition configuration
	ecc_add: EccAddConfig,
	// Integer multiplication selector
	integer_mul_selector: Selector,
}

impl EcdsaConfig {
	/// Construct a new Ecdsa config
	pub fn new(ecc_mul_scalar: EccMulConfig, integer_mul_selector: Selector) -> Self {
		Self { ecc_add: ecc_mul_scalar.add.clone(), ecc_mul_scalar, integer_mul_selector }
	}
}

/// Ecdsa Chipset structure
pub struct EcdsaChipset<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
	EC,
> where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	// Public key
	public_key: AssignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P>,
	// Generator as a ec point
	g_as_ecpoint: AssignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
	// Signature
	signature: AssignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>,
	// Message hash
	msg_hash: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	// Signature inverse
	s_inv: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	// Aux for to_add and to_sub
	aux: AssignedAux<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
	_p: PhantomData<(P, EC)>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
	EcdsaChipset<C, N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	/// Creates a new chipset.
	pub fn new(
		public_key: AssignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P>,
		g_as_ecpoint: AssignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
		signature: AssignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>,
		msg_hash: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
		s_inv: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
		aux: AssignedAux<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
	) -> Self {
		Self { public_key, g_as_ecpoint, signature, msg_hash, s_inv, aux, _p: PhantomData }
	}
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC> Chipset<N>
	for EcdsaChipset<C, N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	type Config = EcdsaConfig;
	type Output = ();

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<N>,
	) -> Result<Self::Output, Error> {
		let r = self.signature.r;

		let u_1_chip = IntegerMulChip::new(self.msg_hash, self.s_inv.clone());
		let u_1 = u_1_chip.synthesize(
			common,
			&config.integer_mul_selector,
			layouter.namespace(|| "u_1"),
		)?;

		let u_2_chip = IntegerMulChip::new(r.clone(), self.s_inv);
		let u_2 = u_2_chip.synthesize(
			common,
			&config.integer_mul_selector,
			layouter.namespace(|| "u_2"),
		)?;

		let v_1_ecc_mul_scalar_chip = EccMulChipset::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::new(
			self.g_as_ecpoint,
			u_1,
			self.aux.clone(),
		);
		let v_1 = v_1_ecc_mul_scalar_chip.synthesize(
			common,
			&config.ecc_mul_scalar,
			layouter.namespace(|| "v_1"),
		)?;

		let v_2_ecc_mul_scalar_chip = EccMulChipset::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::new(
			self.public_key.0, u_2, self.aux,
		);
		let v_2 = v_2_ecc_mul_scalar_chip.synthesize(
			common,
			&config.ecc_mul_scalar,
			layouter.namespace(|| "v_2"),
		)?;

		let r_point_add_chip = EccAddChipset::<C, N, NUM_LIMBS, NUM_BITS, P>::new(v_1, v_2);
		let r_point = r_point_add_chip.synthesize(
			common,
			&config.ecc_add,
			layouter.namespace(|| "r_point"),
		)?;

		let x_candidate = r_point.x;
		layouter.assign_region(
			|| "enforce_equal",
			|region: Region<'_, N>| {
				let mut region_ctx = RegionCtx::new(region, 0);
				for i in 0..NUM_LIMBS {
					region_ctx.constrain_equal(x_candidate.limbs[i].clone(), r.limbs[i].clone())?;
				}
				Ok(())
			},
		)?;

		Ok(())
	}
}

#[derive(Clone)]
/// Assigned ecdsa structure
pub struct AssignedEcdsa<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
	EC,
> where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	pub(crate) auxes: AssignedAux<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
	pub(crate) public_key: AssignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P>,
	pub(crate) g_as_ecpoint: AssignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
	pub(crate) signature: AssignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>,
	pub(crate) msg_hash: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	pub(crate) s_inv: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
	AssignedEcdsa<C, N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	/// Constructor for assigned ecdsa values
	pub fn new(
		auxes: AssignedAux<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
		public_key: AssignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P>,
		g_as_ecpoint: AssignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
		signature: AssignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>,
		msg_hash: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
		s_inv: AssignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { auxes, public_key, g_as_ecpoint, signature, msg_hash, s_inv }
	}
}

#[derive(Clone, Debug)]
/// Config for ecdsa assigner
pub struct EcdsaAssignerConfig {
	aux: AuxConfig,
	mul: Selector,
}

impl EcdsaAssignerConfig {
	/// EcdsaAssignerConfig constructor
	pub fn new(aux: AuxConfig, mul: Selector) -> Self {
		Self { aux, mul }
	}
}

/// Ecdsa assigner struct
pub struct EcdsaAssigner<
	C: CurveAffine,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
	EC,
> where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	public_key: UnassignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
	g_as_ecpoint: UnassignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
	signature: UnassignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>,
	msg_hash: UnassignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	s_inv: UnassignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC>
	EcdsaAssigner<C, N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	/// Creates a new ecdsa assigner object
	pub fn new(
		public_key: UnassignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
		g_as_ecpoint: UnassignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
		signature: UnassignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>,
		msg_hash: UnassignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
		s_inv: UnassignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self { public_key, g_as_ecpoint, signature, msg_hash, s_inv }
	}
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P, EC> Chipset<N>
	for EcdsaAssigner<C, N, NUM_LIMBS, NUM_BITS, P, EC>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::Scalar, N, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	type Config = EcdsaAssignerConfig;
	type Output = AssignedEcdsa<C, N, NUM_LIMBS, NUM_BITS, P, EC>;

	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<N>,
	) -> Result<Self::Output, Error> {
		let aux_assigner = AuxAssigner::<C, N, NUM_LIMBS, NUM_BITS, P, EC>::new();
		let auxes =
			aux_assigner.synthesize(common, &config.aux, layouter.namespace(|| "aux assigner"))?;

		let public_key_assigner = PublicKeyAssigner::new(self.public_key.clone());
		let public_key = public_key_assigner.synthesize(
			common,
			&(),
			layouter.namespace(|| "public_key assigner"),
		)?;

		let g_as_ecpoint_assigner = PointAssigner::new(self.g_as_ecpoint.clone());
		let g_as_ecpoint = g_as_ecpoint_assigner.synthesize(
			common,
			&(),
			layouter.namespace(|| "g_as_ec_point assigner"),
		)?;

		let signature_assigner = SignatureAssigner::new(self.signature.clone());
		let signature = signature_assigner.synthesize(
			common,
			&(),
			layouter.namespace(|| "signature assigner"),
		)?;

		let msg_hash_assigner = IntegerAssigner::new(self.msg_hash.clone());
		let msg_hash = msg_hash_assigner.synthesize(
			common,
			&(),
			layouter.namespace(|| "msg_hash assigner"),
		)?;

		let s_inv_assigner = IntegerAssigner::new(self.s_inv);
		let s_inv =
			s_inv_assigner.synthesize(common, &(), layouter.namespace(|| "s_inv assigner"))?;

		// Constraint for the s_inv
		let mul_chip = IntegerMulChip::new(signature.s.clone(), s_inv.clone());
		let is_one =
			mul_chip.synthesize(common, &config.mul, layouter.namespace(|| "s_inv * s"))?;

		let one_as_unassigned: UnassignedInteger<C::ScalarExt, N, NUM_LIMBS, NUM_BITS, P> =
			UnassignedInteger::from(Integer::one());
		let one_as_assigned = IntegerAssigner::new(one_as_unassigned);
		let one_as_assigned = one_as_assigned.synthesize(
			common,
			&(),
			layouter.namespace(|| "one as assigned integer"),
		)?;

		layouter.assign_region(
			|| "constraint for the s_inv",
			|region: Region<'_, N>| {
				let mut ctx = RegionCtx::new(region, 0);
				for i in 0..NUM_LIMBS {
					ctx.constrain_equal(one_as_assigned.limbs[i].clone(), is_one.limbs[i].clone())?;
				}
				Ok(())
			},
		)?;

		let ecdsa_assigned =
			AssignedEcdsa::new(auxes, public_key, g_as_ecpoint, signature, msg_hash, s_inv);

		Ok(ecdsa_assigned)
	}
}

#[cfg(test)]
mod test {
	use super::native::{PublicKey, Signature};
	use super::{
		EcdsaAssigner, EcdsaAssignerConfig, EcdsaChipset, EcdsaConfig, UnassignedPublicKey,
		UnassignedSignature,
	};
	use crate::ecc::AuxConfig;
	use crate::ecdsa::native::EcdsaKeypair;
	use crate::params::ecc::secp256k1::Secp256k1Params;
	use crate::params::rns::secp256k1::Secp256k1_4_68;
	use crate::utils::big_to_fe;
	use crate::UnassignedValue;
	use crate::{
		ecc::{
			generic::{native::EcPoint, UnassignedEcPoint},
			EccAddConfig, EccDoubleConfig, EccMulConfig, EccTableSelectConfig,
			EccUnreducedLadderConfig,
		},
		gadgets::{
			bits2num::Bits2NumChip,
			main::{MainChip, MainConfig},
		},
		integer::{
			native::Integer, IntegerAddChip, IntegerDivChip, IntegerMulChip, IntegerReduceChip,
			IntegerSubChip, UnassignedInteger,
		},
		Chip, Chipset, CommonConfig,
	};
	use halo2::arithmetic::Field;
	use halo2::dev::MockProver;
	use halo2::halo2curves::ff::PrimeField;
	use halo2::halo2curves::group::Curve;
	use halo2::halo2curves::secp256k1::Secp256k1;
	use halo2::{
		circuit::{Layouter, SimpleFloorPlanner},
		halo2curves::{
			bn256::Fr,
			secp256k1::{Fp, Fq, Secp256k1Affine},
		},
		plonk::{Circuit, ConstraintSystem, Error},
	};

	type W = Fp;
	type SecpScalar = Fq;
	type N = Fr;
	type C = Secp256k1Affine;
	const NUM_LIMBS: usize = 4;
	const NUM_BITS: usize = 68;
	type P = Secp256k1_4_68;
	type EC = Secp256k1Params;

	#[derive(Clone)]
	struct TestConfig {
		common: CommonConfig,
		ecdsa_assigner: EcdsaAssignerConfig,
		ecdsa: EcdsaConfig,
	}

	impl TestConfig {
		fn new(meta: &mut ConstraintSystem<N>) -> Self {
			let common = CommonConfig::new(meta);
			let main = MainConfig::new(MainChip::configure(&common, meta));
			let bits2num_selector = Bits2NumChip::configure(&common, meta);

			let integer_reduce_selector =
				IntegerReduceChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let integer_add_selector =
				IntegerAddChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let integer_sub_selector =
				IntegerSubChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let integer_mul_selector =
				IntegerMulChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let integer_div_selector =
				IntegerDivChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let integer_mul_selector_secp_scalar =
				IntegerMulChip::<SecpScalar, N, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let ecc_add = EccAddConfig::new(
				integer_reduce_selector, integer_sub_selector, integer_mul_selector,
				integer_div_selector,
			);

			let ecc_double = EccDoubleConfig::new(
				integer_reduce_selector, integer_add_selector, integer_sub_selector,
				integer_mul_selector, integer_div_selector,
			);

			let ecc_ladder = EccUnreducedLadderConfig::new(
				integer_add_selector, integer_sub_selector, integer_mul_selector,
				integer_div_selector,
			);

			let ecc_table_select = EccTableSelectConfig::new(main.clone());

			let ecc_mul_scalar = EccMulConfig::new(
				ecc_ladder.clone(),
				ecc_add.clone(),
				ecc_double.clone(),
				ecc_table_select,
				bits2num_selector.clone(),
			);

			let aux = AuxConfig::new(ecc_double);
			let ecdsa_assigner = EcdsaAssignerConfig::new(aux, integer_mul_selector_secp_scalar);

			let ecdsa = EcdsaConfig::new(ecc_mul_scalar, integer_mul_selector_secp_scalar);

			TestConfig { common, ecdsa_assigner, ecdsa }
		}
	}

	#[derive(Clone)]
	struct TestEcdsaCircuit {
		public_key: UnassignedPublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
		g_as_ecpoint: UnassignedEcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
		signature: UnassignedSignature<C, N, NUM_LIMBS, NUM_BITS, P>,
		msg_hash: UnassignedInteger<SecpScalar, N, NUM_LIMBS, NUM_BITS, P>,
		s_inv: UnassignedInteger<SecpScalar, N, NUM_LIMBS, NUM_BITS, P>,
	}

	impl TestEcdsaCircuit {
		fn new(
			public_key: PublicKey<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
			g_as_ecpoint: EcPoint<C, N, NUM_LIMBS, NUM_BITS, P, EC>,
			signature: Signature<C, N, NUM_LIMBS, NUM_BITS, P>,
			msg_hash: Integer<SecpScalar, N, NUM_LIMBS, NUM_BITS, P>,
			s_inv: Integer<SecpScalar, N, NUM_LIMBS, NUM_BITS, P>,
		) -> Self {
			Self {
				public_key: UnassignedPublicKey::new(public_key),
				g_as_ecpoint: UnassignedEcPoint::from(g_as_ecpoint),
				signature: UnassignedSignature::new(signature),
				msg_hash: UnassignedInteger::from(msg_hash),
				s_inv: UnassignedInteger::from(s_inv),
			}
		}
	}

	impl Circuit<Fr> for TestEcdsaCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self {
				public_key: UnassignedPublicKey::without_witnesses(),
				g_as_ecpoint: UnassignedEcPoint::without_witnesses(),
				signature: UnassignedSignature::without_witnesses(),
				msg_hash: UnassignedInteger::without_witnesses(),
				s_inv: UnassignedInteger::without_witnesses(),
			}
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let ecdsa_assigner = EcdsaAssigner::new(
				self.public_key.clone(),
				self.g_as_ecpoint.clone(),
				self.signature.clone(),
				self.msg_hash.clone(),
				self.s_inv.clone(),
			);

			let ecdsa_variables = ecdsa_assigner.synthesize(
				&config.common,
				&config.ecdsa_assigner,
				layouter.namespace(|| "ecdsa_assigner"),
			)?;

			let chip = EcdsaChipset::new(
				ecdsa_variables.public_key, ecdsa_variables.g_as_ecpoint,
				ecdsa_variables.signature, ecdsa_variables.msg_hash, ecdsa_variables.s_inv,
				ecdsa_variables.auxes,
			);

			chip.synthesize(
				&config.common,
				&config.ecdsa,
				layouter.namespace(|| "ecdsa_verify"),
			)?;
			Ok(())
		}
	}

	#[test]
	fn test_ecdsa() {
		// Test Halo2 ECDSA verify
		let rng = &mut rand::thread_rng();
		let keypair =
			EcdsaKeypair::<Secp256k1Affine, Fr, 4, 68, Secp256k1_4_68, Secp256k1Params>::generate_keypair(rng);
		let public_key = keypair.public_key.clone();

		let msg_hash = Fq::from_u128(123456789);
		let msg_hash_integer = Integer::from_w(msg_hash);

		let signature = keypair.sign(msg_hash.clone(), rng);
		let s_inv_fq = big_to_fe::<Fq>(signature.s.value()).invert().unwrap();
		let s_inv = Integer::from_w(s_inv_fq);

		let g = Secp256k1::generator().to_affine();
		let g_as_ecpoint = EcPoint::<Secp256k1Affine, N, NUM_LIMBS, NUM_BITS, P, EC>::new(
			Integer::from_w(g.x),
			Integer::from_w(g.y),
		);

		let circuit =
			TestEcdsaCircuit::new(public_key, g_as_ecpoint, signature, msg_hash_integer, s_inv);
		let k = 15;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}
}
