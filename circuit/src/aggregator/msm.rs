use halo2wrong::{
	curves::{group::Curve, CurveAffine},
	halo2::arithmetic::Field,
};
use std::{
	iter,
	iter::Sum,
	ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[derive(Clone, Debug)]
pub struct MSM<C: Curve> {
	scalar: Option<C::Scalar>,
	bases: Vec<C>,
	scalars: Vec<C::Scalar>,
}

impl<C: Curve> Default for MSM<C> {
	fn default() -> Self {
		Self { scalar: None, scalars: Vec::new(), bases: Vec::new() }
	}
}

impl<C: Curve> MSM<C> {
	pub fn scalar(scalar: C::Scalar) -> Self {
		Self { scalar: Some(scalar), ..Default::default() }
	}

	pub fn base(base: C) -> Self {
		let one = <C::Scalar as Field>::one();
		MSM { scalars: vec![one], bases: vec![base], ..Default::default() }
	}

	pub fn scale(&mut self, factor: &C::Scalar) {
		if let Some(scalar) = self.scalar.as_mut() {
			*scalar *= factor;
		}
		for scalar in self.scalars.iter_mut() {
			*scalar *= factor
		}
	}

	pub fn evaluate(self, gen: C) -> C {
		let pairs = iter::empty()
			.chain(self.scalar.map(|scalar| (scalar, gen)))
			.chain(self.scalars.into_iter().zip(self.bases.into_iter()));
		pairs
			.into_iter()
			.map(|(scalar, base)| base * scalar)
			.reduce(|acc, value| acc + value)
			.unwrap()
	}

	pub fn push(&mut self, scalar: C::Scalar, base: C) {
		if let Some(pos) = self.bases.iter().position(|exist| exist.eq(&base)) {
			self.scalars[pos] += scalar;
		} else {
			self.scalars.push(scalar);
			self.bases.push(base);
		}
	}

	pub fn extend(&mut self, mut other: Self) {
		match (self.scalar.as_mut(), other.scalar.as_ref()) {
			(Some(lhs), Some(rhs)) => *lhs += rhs,
			(None, Some(_)) => self.scalar = other.scalar.take(),
			_ => {},
		};
		for (scalar, base) in other.scalars.into_iter().zip(other.bases) {
			self.push(scalar, base);
		}
	}
}

impl<C: Curve> Add<MSM<C>> for MSM<C> {
	type Output = MSM<C>;

	fn add(mut self, rhs: MSM<C>) -> Self::Output {
		self.extend(rhs);
		self
	}
}

impl<C: Curve> AddAssign<MSM<C>> for MSM<C> {
	fn add_assign(&mut self, rhs: MSM<C>) {
		self.extend(rhs);
	}
}

impl<C: Curve> Sub<MSM<C>> for MSM<C> {
	type Output = MSM<C>;

	fn sub(mut self, rhs: MSM<C>) -> Self::Output {
		self.extend(-rhs);
		self
	}
}

impl<C: Curve> SubAssign<MSM<C>> for MSM<C> {
	fn sub_assign(&mut self, rhs: MSM<C>) {
		self.extend(-rhs);
	}
}

impl<C: Curve> Mul<&C::Scalar> for MSM<C> {
	type Output = MSM<C>;

	fn mul(mut self, rhs: &C::Scalar) -> Self::Output {
		self.scale(rhs);
		self
	}
}

impl<C: Curve> MulAssign<&C::Scalar> for MSM<C> {
	fn mul_assign(&mut self, rhs: &C::Scalar) {
		self.scale(rhs);
	}
}

impl<C: Curve> Neg for MSM<C> {
	type Output = MSM<C>;

	fn neg(mut self) -> MSM<C> {
		self.scalar = self.scalar.map(|scalar| -scalar);
		for scalar in self.scalars.iter_mut() {
			*scalar = -scalar.clone();
		}
		self
	}
}

impl<C: Curve> Sum for MSM<C> {
	fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
		iter.reduce(|acc, item| acc + item).unwrap_or_default()
	}
}
