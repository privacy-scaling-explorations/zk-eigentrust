/// Native version of Ecdsa
pub mod native;

use crate::ecc::generic::EccAddChipset;
use crate::ecc::EccAddConfig;
use crate::{
	ecc::{
		generic::{AssignedPoint, EccMulChipset},
		EccMulConfig,
	},
	integer::{AssignedInteger, IntegerMulChip},
	params::rns::RnsParams,
	Chipset, CommonConfig, FieldExt,
};
use crate::{Chip, RegionCtx};
use halo2::circuit::Region;
use halo2::{
	circuit::Layouter,
	halo2curves::CurveAffine,
	plonk::{Error, Selector},
};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
/// Configuration structure for the Ecdsa
pub struct EcdsaConfig {
	mul_scalar: EccMulConfig,
	add: EccAddConfig,
	integer_mul_selector: Selector,
}

impl EcdsaConfig {
	/// Construct a new Ecdsa config
	pub fn new(
		mul_scalar: EccMulConfig, add: EccAddConfig, integer_mul_selector: Selector,
	) -> Self {
		Self { mul_scalar, add, integer_mul_selector }
	}
}

/// Ecdsa Chipset structure
pub struct EcdsaChipset<
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
	public_key: AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
	g_as_ecpoint: AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
	signature: (
		AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
		AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
	),
	msg_hash: AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
	s_inv: AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
	// AuxInitial (to_add)
	aux_init: AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
	// AuxFinish (to_sub)
	aux_fin: AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
	_p: PhantomData<P>,
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	EcdsaChipset<C, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	/// Creates a new chipset.
	pub fn new(
		public_key: AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
		g_as_ecpoint: AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
		signature: (
			AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
			AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
		),
		msg_hash: AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
		s_inv: AssignedInteger<C::Scalar, N, NUM_LIMBS, NUM_BITS, P>,
		// AuxInitial (to_add)
		aux_init: AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
		// AuxFinish (to_sub)
		aux_fin: AssignedPoint<C, N, NUM_LIMBS, NUM_BITS, P>,
	) -> Self {
		Self {
			public_key,
			g_as_ecpoint,
			signature,
			msg_hash,
			s_inv,
			aux_init,
			aux_fin,
			_p: PhantomData,
		}
	}
}

impl<C: CurveAffine, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Chipset<N>
	for EcdsaChipset<C, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<C::Base, N, NUM_LIMBS, NUM_BITS> + RnsParams<C::ScalarExt, N, NUM_LIMBS, NUM_BITS>,
	C::Base: FieldExt,
	C::ScalarExt: FieldExt,
{
	type Config = EcdsaConfig;
	type Output = ();

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<N>,
	) -> Result<Self::Output, Error> {
		let (r, _) = &self.signature;

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

		let v_1_mul_scalar_chip = EccMulChipset::<C, N, NUM_LIMBS, NUM_BITS, P>::new(
			self.g_as_ecpoint,
			u_1,
			self.aux_init.clone(),
			self.aux_fin.clone(),
		);
		let v_1 = v_1_mul_scalar_chip.synthesize(
			common,
			&config.mul_scalar,
			layouter.namespace(|| "v_1"),
		)?;

		let v_2_mul_scalar_chip = EccMulChipset::<C, N, NUM_LIMBS, NUM_BITS, P>::new(
			self.public_key,
			u_2,
			self.aux_init.clone(),
			self.aux_fin.clone(),
		);
		let v_2 = v_2_mul_scalar_chip.synthesize(
			common,
			&config.mul_scalar,
			layouter.namespace(|| "v_2"),
		)?;

		//let r_point = v_1.add(&v_2);
		let r_point_add_chip = EccAddChipset::<C, N, NUM_LIMBS, NUM_BITS, P>::new(v_1, v_2);
		let r_point =
			r_point_add_chip.synthesize(common, &config.add, layouter.namespace(|| "r_point"))?;

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
