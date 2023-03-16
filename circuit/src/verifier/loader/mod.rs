use crate::{
	ecc::EccMulConfig,
	gadgets::main::{InverseChipset, MainConfig},
	integer::rns::RnsParams,
	poseidon::sponge::PoseidonSpongeConfig,
	Chipset, CommonConfig,
};
use halo2::{
	circuit::{AssignedCell, Layouter},
	halo2curves::CurveAffine,
};
use native::{NUM_BITS, NUM_LIMBS};
use snark_verifier::util::arithmetic::FieldOps;
use std::{
	marker::PhantomData,
	ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
	rc::Rc,
	sync::Mutex,
};

/// Native version of the loader
pub mod native;

// TODO: FOR Halo2LScalar: Use AssignedCell for inner value
// TODO: For Halo2LEcPoint: Use AssignedPoint for inner value

// TODO: Rename to LoaderConfig
/// Halo2Loader
pub struct Halo2Loader<C: CurveAffine, L: Layouter<C::Scalar>, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	layouter: Rc<Mutex<L>>,
	common: CommonConfig,
	ecc_mul_scalar: EccMulConfig,
	main: MainConfig,
	poseidon_sponge: PoseidonSpongeConfig,
	_curve: PhantomData<C>,
	_p: PhantomData<P>,
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Halo2Loader<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Construct new Halo2Loader
	pub fn new(
		layouter: Rc<Mutex<L>>, common: CommonConfig, ecc_mul_scalar: EccMulConfig,
		main: MainConfig, poseidon_sponge: PoseidonSpongeConfig,
	) -> Self {
		Self {
			layouter,
			common,
			ecc_mul_scalar,
			main,
			poseidon_sponge,
			_curve: PhantomData,
			_p: PhantomData,
		}
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Clone for Halo2Loader<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn clone(&self) -> Self {
		Self {
			layouter: self.layouter.clone(),
			common: self.common.clone(),
			ecc_mul_scalar: self.ecc_mul_scalar.clone(),
			main: self.main.clone(),
			poseidon_sponge: self.poseidon_sponge.clone(),
			_curve: PhantomData,
			_p: PhantomData,
		}
	}
}

struct Halo2LScalar<C: CurveAffine, L: Layouter<C::Scalar>, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	inner: AssignedCell<C::Scalar, C::Scalar>,
	loader: Halo2Loader<C, L, P>,
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	pub fn new(value: AssignedCell<C::Scalar, C::Scalar>, loader: Halo2Loader<C, L, P>) -> Self {
		return Self { inner: value, loader };
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> FieldOps for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn invert(&self) -> Option<Self> {
		let mut loader_ref = self.loader.layouter.lock().unwrap();
		let inv_chipset = InverseChipset::new(self.inner.clone());
		let inv_op = inv_chipset.synthesize(
			&self.loader.common,
			&self.loader.main,
			loader_ref.namespace(|| "loader_inverse"),
		);
		inv_op.ok().map(|x| Self { inner: x, loader: self.loader.clone() })
	}
}

// ---- ADD ----

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> Add<&'a Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = Self;

	fn add(self, rhs: &'a Self) -> Self {
		self
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Add<Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = Self;

	fn add(self, rhs: Self) -> Self {
		self
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> AddAssign<&'a Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn add_assign(&mut self, rhs: &'a Self) {}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> AddAssign<Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn add_assign(&mut self, rhs: Self) {}
}

// ---- MUL ----

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> Mul<&'a Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = Self;

	fn mul(self, rhs: &'a Self) -> Self {
		self
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Mul<Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = Self;

	fn mul(self, rhs: Self) -> Self {
		self
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> MulAssign<&'a Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn mul_assign(&mut self, rhs: &'a Self) {}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> MulAssign<Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn mul_assign(&mut self, rhs: Self) {}
}

// ---- SUB ----

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> Sub<&'a Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = Self;

	fn sub(self, rhs: &'a Self) -> Self {
		self
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Sub<Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = Self;

	fn sub(self, rhs: Self) -> Self {
		self
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> SubAssign<&'a Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn sub_assign(&mut self, rhs: &'a Self) {}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> SubAssign<Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn sub_assign(&mut self, rhs: Self) {}
}

// ---- NEG ----

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Neg for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = Self;

	fn neg(self) -> Self {
		self
	}
}

// TODO: Implement LoadedScalar for Halo2LScalar
// TODO: Implement ScalarLoader for Halo2LScalar
// ----- load_const: Open a new region and
// assign constant value to a fixed column
// ----- assert_eq: Open a new region and call ctx.constrain_equal passing the
// loaded scalars

// TODO: Implement Halo2LEcPoint struct
// TODO: Implement LoadedEcPoint for Halo2LEcPoint
// ---- ec_point_load_const: Open a new region and decompose CurveAffine values
// into limbs and assign each limb into a fixed column
// ---- ec_point_assert_eq: Open a new region and call ctx.constrain_equal for
// each limb
// ---- multi_scalar_multiplication: Call mul_scalar and add chips for ecc
