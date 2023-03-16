use crate::{
	ecc::{AssignedPoint, EccMulConfig},
	gadgets::main::{AddChipset, InverseChipset, MainConfig, MulChipset, SubChipset},
	integer::rns::RnsParams,
	poseidon::sponge::PoseidonSpongeConfig,
	Chipset, CommonConfig, RegionCtx,
};
use halo2::{
	circuit::{AssignedCell, Layouter, Region},
	halo2curves::CurveAffine,
};
use native::{NUM_BITS, NUM_LIMBS};
use snark_verifier::{
	loader::{EcPointLoader, LoadedEcPoint, LoadedScalar, ScalarLoader},
	util::arithmetic::FieldOps,
	Error::AssertionFailure,
};
use std::{
	fmt::Debug,
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

/// Halo2 loaded scalar structure
pub struct Halo2LScalar<C: CurveAffine, L: Layouter<C::Scalar>, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	inner: AssignedCell<C::Scalar, C::Scalar>,
	loader: Halo2Loader<C, L, P>,
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Clone for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn clone(&self) -> Self {
		Self { inner: self.inner.clone(), loader: self.loader.clone() }
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Debug for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Halo2LScalar").field("inner", &self.inner).finish()
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> PartialEq for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn eq(&self, other: &Self) -> bool {
		let mut layouter = self.loader.layouter.lock().unwrap();
		let _ = layouter.assign_region(
			|| "eq",
			|region: Region<'_, C::Scalar>| {
				let mut ctx = RegionCtx::new(region, 0);
				let eq = ctx.constrain_equal(self.inner.clone(), other.inner.clone())?;
				Ok(eq)
			},
		);
		true
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Creates a new Halo2LScalar
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
		let mut loader_ref = self.loader.layouter.lock().unwrap();
		let add_chipset = AddChipset::new(self.inner, rhs.inner.clone());
		let add = add_chipset
			.synthesize(
				&self.loader.common,
				&self.loader.main,
				loader_ref.namespace(|| "loader_add"),
			)
			.unwrap();
		Self { inner: add, loader: self.loader.clone() }
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Add<Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = Self;

	fn add(self, rhs: Self) -> Self {
		self.add(&rhs)
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> AddAssign<&'a Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn add_assign(&mut self, rhs: &'a Self) {
		*self = self.clone().add(rhs);
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> AddAssign<Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn add_assign(&mut self, rhs: Self) {
		self.add_assign(&rhs)
	}
}

// ---- MUL ----

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> Mul<&'a Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = Self;

	fn mul(self, rhs: &'a Self) -> Self {
		let mut loader_ref = self.loader.layouter.lock().unwrap();
		let mul_chipset = MulChipset::new(self.inner, rhs.inner.clone());
		let mul = mul_chipset
			.synthesize(
				&self.loader.common,
				&self.loader.main,
				loader_ref.namespace(|| "loader_mul"),
			)
			.unwrap();
		Self { inner: mul, loader: self.loader.clone() }
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Mul<Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = Self;

	fn mul(self, rhs: Self) -> Self {
		self.mul(&rhs)
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> MulAssign<&'a Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn mul_assign(&mut self, rhs: &'a Self) {
		*self = self.clone().mul(rhs);
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> MulAssign<Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn mul_assign(&mut self, rhs: Self) {
		self.mul_assign(&rhs)
	}
}

// ---- SUB ----

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> Sub<&'a Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = Self;

	fn sub(self, rhs: &'a Self) -> Self {
		let mut loader_ref = self.loader.layouter.lock().unwrap();
		let sub_chipset = SubChipset::new(self.inner, rhs.inner.clone());
		let sub = sub_chipset
			.synthesize(
				&self.loader.common,
				&self.loader.main,
				loader_ref.namespace(|| "loader_sub"),
			)
			.unwrap();
		Self { inner: sub, loader: self.loader.clone() }
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Sub<Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = Self;

	fn sub(self, rhs: Self) -> Self {
		self.sub(&rhs)
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> SubAssign<&'a Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn sub_assign(&mut self, rhs: &'a Self) {
		*self = self.clone().sub(rhs);
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> SubAssign<Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn sub_assign(&mut self, rhs: Self) {
		self.sub_assign(&rhs)
	}
}

// ---- NEG ----

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Neg for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = Self;

	fn neg(self) -> Self {
		let mut loader_ref = self.loader.layouter.lock().unwrap();
		let sub_chipset = SubChipset::new(self.inner.clone(), self.inner.clone());
		let zero = sub_chipset
			.synthesize(
				&self.loader.common,
				&self.loader.main,
				loader_ref.namespace(|| "loader_sub"),
			)
			.unwrap();
		let sub_chipset = SubChipset::new(zero, self.inner);
		let neg = sub_chipset
			.synthesize(
				&self.loader.common,
				&self.loader.main,
				loader_ref.namespace(|| "loader_sub"),
			)
			.unwrap();
		Self { inner: neg, loader: self.loader.clone() }
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> LoadedScalar<C::Scalar> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Loader = Halo2Loader<C, L, P>;

	/// Returns loader.
	fn loader(&self) -> &Self::Loader {
		&self.loader
	}
}

// TODO: Ask why this is not under the Halo2Loader in native
impl<C: CurveAffine, L: Layouter<C::Scalar>, P> ScalarLoader<C::Scalar> for Halo2Loader<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type LoadedScalar = Halo2LScalar<C, L, P>;

	fn load_const(&self, value: &C::Scalar) -> Self::LoadedScalar {
		let mut layouter = self.layouter.lock().unwrap();
		let assigned_value = layouter
			.assign_region(
				|| "load_const",
				|region: Region<'_, C::Scalar>| {
					let mut ctx = RegionCtx::new(region, 0);
					ctx.assign_fixed(self.common.fixed[0], value.clone())
				},
			)
			.unwrap();
		Halo2LScalar::new(assigned_value, self.clone())
	}

	fn assert_eq(
		&self, annotation: &str, lhs: &Self::LoadedScalar, rhs: &Self::LoadedScalar,
	) -> Result<(), snark_verifier::Error> {
		let mut layouter = self.layouter.lock().unwrap();
		layouter
			.assign_region(
				|| "eq",
				|region: Region<'_, C::Scalar>| {
					let mut ctx = RegionCtx::new(region, 0);
					ctx.constrain_equal(lhs.inner.clone(), rhs.inner.clone())
				},
			)
			.ok()
			.ok_or_else(|| AssertionFailure(annotation.to_string()))
	}
}

/// Halo2 loaded ec point structure
pub struct Halo2LEcPoint<C: CurveAffine, L: Layouter<C::Scalar>, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	inner: AssignedPoint<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS, P>,
	loader: Halo2Loader<C, L, P>,
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Clone for Halo2LEcPoint<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn clone(&self) -> Self {
		Self { inner: self.inner.clone(), loader: self.loader.clone() }
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Debug for Halo2LEcPoint<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Halo2LEcPoint").field("inner", &self.inner).finish()
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> PartialEq for Halo2LEcPoint<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	// TODO: Ask return of the eq functions
	fn eq(&self, other: &Self) -> bool {
		let mut layouter = self.loader.layouter.lock().unwrap();
		let _ = layouter.assign_region(
			|| "eq",
			|region: Region<'_, C::Scalar>| {
				let mut ctx = RegionCtx::new(region, 0);
				for i in 0..NUM_LIMBS {
					ctx.constrain_equal(
						self.inner.x.limbs[i].clone(),
						other.inner.x.limbs[i].clone(),
					)?;
					ctx.constrain_equal(
						self.inner.y.limbs[i].clone(),
						other.inner.y.limbs[i].clone(),
					)?;
				}
				Ok(())
			},
		);
		true
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> LoadedEcPoint<C> for Halo2LEcPoint<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Loader = Halo2Loader<C, L, P>;

	/// Returns loader.
	fn loader(&self) -> &Self::Loader {
		&self.loader
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> EcPointLoader<C> for Halo2Loader<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type LoadedEcPoint = Halo2LEcPoint<C, L, P>;

	fn ec_point_load_const(&self, value: &C) -> Self::LoadedEcPoint {
		todo!()
	}

	fn ec_point_assert_eq(
		&self, annotation: &str, lhs: &Self::LoadedEcPoint, rhs: &Self::LoadedEcPoint,
	) -> Result<(), snark_verifier::Error> {
		todo!()
	}

	fn multi_scalar_multiplication(
		pairs: &[(
			&<Self as ScalarLoader<C::Scalar>>::LoadedScalar,
			&Self::LoadedEcPoint,
		)],
	) -> Self::LoadedEcPoint
	where
		Self: ScalarLoader<<C as CurveAffine>::ScalarExt>,
	{
		todo!()
	}
}

// TODO: Implement LoadedEcPoint for Halo2LEcPoint
// ---- ec_point_load_const: Open a new region and decompose CurveAffine values
// into limbs and assign each limb into a fixed column
// ---- ec_point_assert_eq: Open a new region and call ctx.constrain_equal for
// each limb
// ---- multi_scalar_multiplication: Call mul_scalar and add chips for ecc
