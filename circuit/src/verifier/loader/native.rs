use crate::{
	ecc::native::EcPoint,
	integer::native::Integer,
	params::{ecc::EccParams, rns::RnsParams},
	FieldExt,
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
pub struct NativeLoader<C: CurveAffine, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	// PhantomData
	pub(crate) _c: PhantomData<C>,
	pub(crate) _p: PhantomData<P>,
	_ec: PhantomData<EC>,
}

impl<C: CurveAffine, P, EC> NativeLoader<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Construct a new NativeLoader
	pub fn new() -> Self {
		Self { _c: PhantomData, _p: PhantomData, _ec: PhantomData }
	}
}

#[derive(Debug, Default, Clone, PartialEq)]
/// LScalar structure
pub struct LScalar<C: CurveAffine, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	// Inner value for the loaded scalar
	pub(crate) inner: C::Scalar,
	// Loader
	pub(crate) loader: NativeLoader<C, P, EC>,

	_ec: PhantomData<EC>,
}

impl<C: CurveAffine, P, EC> LScalar<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Construct a new LScalar
	pub fn new(value: C::Scalar, loader: NativeLoader<C, P, EC>) -> Self {
		Self { inner: value, loader, _ec: PhantomData }
	}
}

impl<C: CurveAffine, P, EC> FieldOps for LScalar<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Returns multiplicative inversion if any.
	fn invert(&self) -> Option<Self> {
		let inv = Field::invert(&self.inner.clone());
		let inv_op: Option<C::Scalar> = inv.into();
		inv_op.map(|x| Self::new(x, self.loader.clone()))
	}
}

// ---- ADD ----

impl<'a, C: CurveAffine, P, EC> Add<&'a LScalar<C, P, EC>> for LScalar<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Output = LScalar<C, P, EC>;

	/// Performs the `+` operation.
	fn add(self, rhs: &'a LScalar<C, P, EC>) -> Self::Output {
		let res = self.inner + rhs.inner;
		Self::new(res, self.loader)
	}
}

impl<C: CurveAffine, P, EC> Add<LScalar<C, P, EC>> for LScalar<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Output = LScalar<C, P, EC>;

	/// Performs the `+` operation.
	fn add(self, rhs: LScalar<C, P, EC>) -> Self::Output {
		self.add(&rhs)
	}
}

impl<'a, C: CurveAffine, P, EC> AddAssign<&'a LScalar<C, P, EC>> for LScalar<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Performs the `+=` operation.
	fn add_assign(&mut self, rhs: &'a LScalar<C, P, EC>) {
		*self = self.clone().add(rhs);
	}
}

impl<C: CurveAffine, P, EC> AddAssign<LScalar<C, P, EC>> for LScalar<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Performs the `+=` operation.
	fn add_assign(&mut self, rhs: LScalar<C, P, EC>) {
		self.add_assign(&rhs)
	}
}

// ---- MUL ----

impl<'a, C: CurveAffine, P, EC> Mul<&'a LScalar<C, P, EC>> for LScalar<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Output = LScalar<C, P, EC>;

	/// Performs the `*` operation.
	fn mul(self, rhs: &'a LScalar<C, P, EC>) -> Self::Output {
		let res = self.inner * rhs.inner;
		Self::new(res, self.loader)
	}
}

impl<C: CurveAffine, P, EC> Mul<LScalar<C, P, EC>> for LScalar<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Output = LScalar<C, P, EC>;

	/// Performs the `*` operation.
	fn mul(self, rhs: LScalar<C, P, EC>) -> Self::Output {
		self.mul(&rhs)
	}
}

impl<'a, C: CurveAffine, P, EC> MulAssign<&'a LScalar<C, P, EC>> for LScalar<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Performs the `*=` operation.
	fn mul_assign(&mut self, rhs: &'a LScalar<C, P, EC>) {
		*self = self.clone().mul(rhs);
	}
}

impl<C: CurveAffine, P, EC> MulAssign<LScalar<C, P, EC>> for LScalar<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Performs the `*=` operation.
	fn mul_assign(&mut self, rhs: LScalar<C, P, EC>) {
		self.mul_assign(&rhs)
	}
}

// ---- SUB ----

impl<'a, C: CurveAffine, P, EC> Sub<&'a LScalar<C, P, EC>> for LScalar<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Output = LScalar<C, P, EC>;

	/// Performs the `-` operation.
	fn sub(self, rhs: &'a LScalar<C, P, EC>) -> Self::Output {
		let res = self.inner - rhs.inner;
		Self::new(res, self.loader)
	}
}

impl<C: CurveAffine, P, EC> Sub<LScalar<C, P, EC>> for LScalar<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Output = LScalar<C, P, EC>;

	/// Performs the `-` operation.
	fn sub(self, rhs: LScalar<C, P, EC>) -> Self::Output {
		self.sub(&rhs)
	}
}

impl<'a, C: CurveAffine, P, EC> SubAssign<&'a LScalar<C, P, EC>> for LScalar<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Performs the `-=` operation.
	fn sub_assign(&mut self, rhs: &'a LScalar<C, P, EC>) {
		*self = self.clone().sub(rhs);
	}
}

impl<C: CurveAffine, P, EC> SubAssign<LScalar<C, P, EC>> for LScalar<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Performs the `-=` operation.
	fn sub_assign(&mut self, rhs: LScalar<C, P, EC>) {
		self.sub_assign(&rhs)
	}
}

// ---- NEG ----

impl<C: CurveAffine, P, EC> Neg for LScalar<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Output = Self;

	/// Performs the unary `-` operation.
	fn neg(self) -> Self::Output {
		let res = C::Scalar::neg(self.inner.clone());
		Self::new(res, self.loader)
	}
}

impl<C: CurveAffine, P, EC> LoadedScalar<C::Scalar> for LScalar<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// [`Loader`].
	type Loader = NativeLoader<C, P, EC>;

	/// Returns [`Loader`].
	fn loader(&self) -> &Self::Loader {
		&self.loader
	}
}

impl<C: CurveAffine, P, EC> ScalarLoader<C::Scalar> for NativeLoader<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// [`LoadedScalar`].
	type LoadedScalar = LScalar<C, P, EC>;

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
pub struct LEcPoint<C: CurveAffine, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	// Inner value for the loaded point
	pub(crate) inner: EcPoint<C, NUM_LIMBS, NUM_BITS, P, EC>,
	// Loader
	pub(crate) loader: NativeLoader<C, P, EC>,
}

impl<C: CurveAffine, P, EC> LEcPoint<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Construct a new LEcPoint
	pub fn new(
		value: EcPoint<C, NUM_LIMBS, NUM_BITS, P, EC>, loader: NativeLoader<C, P, EC>,
	) -> Self {
		Self { inner: value, loader }
	}
}

impl<C: CurveAffine, P, EC> LoadedEcPoint<C> for LEcPoint<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Loader = NativeLoader<C, P, EC>;

	/// Returns [`Loader`].
	fn loader(&self) -> &Self::Loader {
		&self.loader
	}
}

impl<C: CurveAffine, P, EC> EcPointLoader<C> for NativeLoader<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type LoadedEcPoint = LEcPoint<C, P, EC>;

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

impl<C: CurveAffine, P, EC> Loader<C> for NativeLoader<C, P, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
}
