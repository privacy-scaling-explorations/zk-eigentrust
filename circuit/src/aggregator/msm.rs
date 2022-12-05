use super::{NUM_BITS, NUM_LIMBS};
use crate::{ecc::native::EcPoint, integer::rns::RnsParams};
use halo2wrong::{
	curves::{
		group::{ff::PrimeField, Curve},
		CurveAffine, FieldExt,
	},
	halo2::arithmetic::Field,
};
use std::{
	iter::{self, Sum},
	ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[derive(Clone, Debug)]
pub struct MSM<C: CurveAffine, R>
where
	R: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	scalar: Option<C::ScalarExt>,
	bases: Vec<EcPoint<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, R>>,
	scalars: Vec<C::ScalarExt>,
}

impl<C: CurveAffine, R> Default for MSM<C, R>
where
	R: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	fn default() -> Self {
		Self { scalar: None, scalars: Vec::new(), bases: Vec::new() }
	}
}

impl<C: CurveAffine, R> MSM<C, R>
where
	R: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	pub fn scalar(scalar: C::ScalarExt) -> Self {
		Self { scalar: Some(scalar), ..Default::default() }
	}

	pub fn base(base: EcPoint<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, R>) -> Self {
		let one = C::ScalarExt::one();
		MSM { scalars: vec![one], bases: vec![base], ..Default::default() }
	}

	pub fn scale(&mut self, factor: &C::ScalarExt) {
		if let Some(scalar) = self.scalar.as_mut() {
			*scalar *= factor;
		}
		for scalar in self.scalars.iter_mut() {
			*scalar *= factor
		}
	}

	pub fn evaluate(
		self, gen: EcPoint<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, R>,
	) -> EcPoint<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, R> {
		let pairs = iter::empty()
			.chain(self.scalar.map(|scalar| (scalar, gen)))
			.chain(self.scalars.into_iter().zip(self.bases.into_iter()));
		pairs
			.into_iter()
			.map(|(scalar, base)| {
				base.mul_scalar(<C::ScalarExt as PrimeField>::to_repr(&scalar).as_ref())
			})
			.reduce(|acc, value| acc.add(&value))
			.unwrap()
	}

	pub fn push(
		&mut self, scalar: C::ScalarExt,
		base: EcPoint<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, R>,
	) {
		if let Some(pos) = self.bases.iter().position(|exist| exist.is_eq(&base)) {
			self.scalars[pos] += scalar;
		} else {
			self.scalars.push(scalar);
			self.bases.push(base);
		}
	}

	pub fn extend(&mut self, mut other: Self) {
		match (self.scalar.as_mut(), other.scalar.as_ref()) {
			(Some(lhs), Some(rhs)) => *lhs += *rhs,
			(None, Some(_)) => self.scalar = other.scalar.take(),
			_ => {},
		};
		for (scalar, base) in other.scalars.into_iter().zip(other.bases) {
			self.push(scalar, base);
		}
	}
}

impl<C: CurveAffine, R> Add<MSM<C, R>> for MSM<C, R>
where
	R: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	type Output = MSM<C, R>;

	fn add(mut self, rhs: MSM<C, R>) -> Self::Output {
		self.extend(rhs);
		self
	}
}

impl<C: CurveAffine, R> AddAssign<MSM<C, R>> for MSM<C, R>
where
	R: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	fn add_assign(&mut self, rhs: MSM<C, R>) {
		self.extend(rhs);
	}
}

impl<C: CurveAffine, R> Sub<MSM<C, R>> for MSM<C, R>
where
	R: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	type Output = MSM<C, R>;

	fn sub(mut self, rhs: MSM<C, R>) -> Self::Output {
		self.extend(-rhs);
		self
	}
}

impl<C: CurveAffine, R> SubAssign<MSM<C, R>> for MSM<C, R>
where
	R: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	fn sub_assign(&mut self, rhs: MSM<C, R>) {
		self.extend(-rhs);
	}
}

impl<C: CurveAffine, R> Mul<&C::ScalarExt> for MSM<C, R>
where
	R: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	type Output = MSM<C, R>;

	fn mul(mut self, rhs: &C::ScalarExt) -> Self::Output {
		self.scale(rhs);
		self
	}
}

impl<C: CurveAffine, R> MulAssign<&C::ScalarExt> for MSM<C, R>
where
	R: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	fn mul_assign(&mut self, rhs: &C::ScalarExt) {
		self.scale(rhs);
	}
}

impl<C: CurveAffine, R> Neg for MSM<C, R>
where
	R: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	type Output = MSM<C, R>;

	fn neg(mut self) -> MSM<C, R> {
		self.scalar = self.scalar.map(|scalar| -scalar);
		for scalar in self.scalars.iter_mut() {
			*scalar = -scalar.clone();
		}
		self
	}
}

impl<C: CurveAffine, R> Sum for MSM<C, R>
where
	R: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
		iter.reduce(|acc, item| acc + item).unwrap_or_default()
	}
}
