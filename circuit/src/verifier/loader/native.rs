use crate::{
	ecc::native::EcPoint,
	integer::{native::Integer, rns::RnsParams},
};
use halo2::{
	arithmetic::Field,
	halo2curves::{Coordinates, CurveAffine},
};
use snark_verifier::{
	loader::{EcPointLoader, LoadedEcPoint, LoadedScalar, Loader, ScalarLoader},
	util::arithmetic::FieldOps,
	Error as VerifierError,
};
use std::{
	fmt::Debug,
	marker::PhantomData,
	ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

/// NUM_LIMBS
pub const NUM_LIMBS: usize = 4;
/// NUM_BITS
pub const NUM_BITS: usize = 68;

#[derive(Debug, Default, Clone, PartialEq)]
/// NativeLoader structure
pub struct NativeLoader<C: CurveAffine, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	// PhantomData
	pub(crate) _c: PhantomData<C>,
	pub(crate) _p: PhantomData<P>,
}

impl<C: CurveAffine, P> NativeLoader<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Construct a new NativeLoader
	pub fn new() -> Self {
		Self { _c: PhantomData, _p: PhantomData }
	}
}

#[derive(Debug, Default, Clone, PartialEq)]
/// LScalar structure
pub struct LScalar<C: CurveAffine, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	// Inner value for the loaded scalar
	pub(crate) inner: C::Scalar,
	// Loader
	pub(crate) loader: NativeLoader<C, P>,
}

impl<C: CurveAffine, P> LScalar<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Construct a new LScalar
	pub fn new(value: C::Scalar, loader: NativeLoader<C, P>) -> Self {
		Self { inner: value, loader }
	}
}

impl<C: CurveAffine, P> FieldOps for LScalar<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Returns multiplicative inversion if any.
	fn invert(&self) -> Option<Self> {
		let inv = Field::invert(&self.inner.clone());
		let inv_op: Option<C::Scalar> = inv.into();
		inv_op.map(|x| Self { inner: x, loader: self.loader.clone() })
	}
}

// ---- ADD ----

impl<'a, C: CurveAffine, P> Add<&'a LScalar<C, P>> for LScalar<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = LScalar<C, P>;

	/// Performs the `+` operation.
	fn add(self, rhs: &'a LScalar<C, P>) -> Self::Output {
		let res = self.inner + rhs.inner;
		Self { inner: res, loader: self.loader.clone() }
	}
}

impl<C: CurveAffine, P> Add<LScalar<C, P>> for LScalar<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = LScalar<C, P>;

	/// Performs the `+` operation.
	fn add(self, rhs: LScalar<C, P>) -> Self::Output {
		self.add(&rhs)
	}
}

impl<'a, C: CurveAffine, P> AddAssign<&'a LScalar<C, P>> for LScalar<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Performs the `+=` operation.
	fn add_assign(&mut self, rhs: &'a LScalar<C, P>) {
		*self = self.clone().add(rhs);
	}
}

impl<C: CurveAffine, P> AddAssign<LScalar<C, P>> for LScalar<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Performs the `+=` operation.
	fn add_assign(&mut self, rhs: LScalar<C, P>) {
		self.add_assign(&rhs)
	}
}

// ---- MUL ----

impl<'a, C: CurveAffine, P> Mul<&'a LScalar<C, P>> for LScalar<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = LScalar<C, P>;

	/// Performs the `*` operation.
	fn mul(self, rhs: &'a LScalar<C, P>) -> Self::Output {
		let res = self.inner * rhs.inner;
		Self { inner: res, loader: self.loader.clone() }
	}
}

impl<C: CurveAffine, P> Mul<LScalar<C, P>> for LScalar<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = LScalar<C, P>;

	/// Performs the `*` operation.
	fn mul(self, rhs: LScalar<C, P>) -> Self::Output {
		self.mul(&rhs)
	}
}

impl<'a, C: CurveAffine, P> MulAssign<&'a LScalar<C, P>> for LScalar<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Performs the `*=` operation.
	fn mul_assign(&mut self, rhs: &'a LScalar<C, P>) {
		*self = self.clone().mul(rhs);
	}
}

impl<C: CurveAffine, P> MulAssign<LScalar<C, P>> for LScalar<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Performs the `*=` operation.
	fn mul_assign(&mut self, rhs: LScalar<C, P>) {
		self.mul_assign(&rhs)
	}
}

// ---- SUB ----

impl<'a, C: CurveAffine, P> Sub<&'a LScalar<C, P>> for LScalar<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = LScalar<C, P>;

	/// Performs the `-` operation.
	fn sub(self, rhs: &'a LScalar<C, P>) -> Self::Output {
		let res = self.inner - rhs.inner;
		Self { inner: res, loader: self.loader.clone() }
	}
}

impl<C: CurveAffine, P> Sub<LScalar<C, P>> for LScalar<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = LScalar<C, P>;

	/// Performs the `-` operation.
	fn sub(self, rhs: LScalar<C, P>) -> Self::Output {
		self.sub(&rhs)
	}
}

impl<'a, C: CurveAffine, P> SubAssign<&'a LScalar<C, P>> for LScalar<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Performs the `-=` operation.
	fn sub_assign(&mut self, rhs: &'a LScalar<C, P>) {
		*self = self.clone().sub(rhs);
	}
}

impl<C: CurveAffine, P> SubAssign<LScalar<C, P>> for LScalar<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Performs the `-=` operation.
	fn sub_assign(&mut self, rhs: LScalar<C, P>) {
		self.sub_assign(&rhs)
	}
}

// ---- NEG ----

impl<C: CurveAffine, P> Neg for LScalar<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Output = Self;

	/// Performs the unary `-` operation.
	fn neg(self) -> Self::Output {
		let res = C::Scalar::neg(self.inner.clone());
		Self { inner: res, loader: self.loader.clone() }
	}
}

impl<C: CurveAffine, P> LoadedScalar<C::Scalar> for LScalar<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// [`Loader`].
	type Loader = NativeLoader<C, P>;

	/// Returns [`Loader`].
	fn loader(&self) -> &Self::Loader {
		&self.loader
	}
}

impl<C: CurveAffine, P> ScalarLoader<C::Scalar> for NativeLoader<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// [`LoadedScalar`].
	type LoadedScalar = LScalar<C, P>;

	/// Load a constant field element.
	fn load_const(&self, value: &C::Scalar) -> Self::LoadedScalar {
		LScalar::new(value.clone(), self.clone())
	}

	/// Assert lhs and rhs field elements are equal.
	fn assert_eq(
		&self, annotation: &str, lhs: &Self::LoadedScalar, rhs: &Self::LoadedScalar,
	) -> Result<(), VerifierError> {
		lhs.eq(rhs)
			.then_some(())
			.ok_or_else(|| VerifierError::AssertionFailure(annotation.to_string()))
	}
}

#[derive(Debug, Default, Clone, PartialEq)]
/// LEcPoint structure
pub struct LEcPoint<C: CurveAffine, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	// Inner value for the loaded point
	pub(crate) inner: EcPoint<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS, P>,
	// Loader
	pub(crate) loader: NativeLoader<C, P>,
}

impl<C: CurveAffine, P> LEcPoint<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Construct a new LEcPoint
	pub fn new(
		value: EcPoint<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS, P>, loader: NativeLoader<C, P>,
	) -> Self {
		Self { inner: value, loader }
	}
}

impl<C: CurveAffine, P> LoadedEcPoint<C> for LEcPoint<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Loader = NativeLoader<C, P>;

	/// Returns [`Loader`].
	fn loader(&self) -> &Self::Loader {
		&self.loader
	}
}

impl<C: CurveAffine, P> EcPointLoader<C> for NativeLoader<C, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type LoadedEcPoint = LEcPoint<C, P>;

	/// Load a constant elliptic curve point.
	fn ec_point_load_const(&self, value: &C) -> Self::LoadedEcPoint {
		let coords: Coordinates<C> = Option::from(value.coordinates()).unwrap();
		let x = Integer::from_w(coords.x().clone());
		let y = Integer::from_w(coords.y().clone());
		let point = EcPoint::new(x, y);

		LEcPoint::new(point, self.clone())
	}

	/// Assert lhs and rhs elliptic curve points are equal.
	fn ec_point_assert_eq(
		&self, annotation: &str, lhs: &Self::LoadedEcPoint, rhs: &Self::LoadedEcPoint,
	) -> Result<(), VerifierError> {
		lhs.eq(rhs)
			.then_some(())
			.ok_or_else(|| VerifierError::AssertionFailure(annotation.to_string()))
	}

	/// Perform multi-scalar multiplication.
	fn multi_scalar_multiplication(
		pairs: &[(
			&<Self as ScalarLoader<C::Scalar>>::LoadedScalar,
			&Self::LoadedEcPoint,
		)],
	) -> Self::LoadedEcPoint {
		let point = pairs
			.iter()
			.cloned()
			.map(|(scalar, base)| {
				let new = scalar.clone();
				base.inner.mul_scalar(new.inner)
			})
			.reduce(|acc, value| acc.add(&value))
			.unwrap();
		LEcPoint::new(point, pairs[0].1.loader.clone())
	}
}

impl<C: CurveAffine, P> Loader<C> for NativeLoader<C, P> where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>
{
}
