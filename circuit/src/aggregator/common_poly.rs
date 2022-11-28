use super::protocol::Rotation;
use halo2wrong::curves::{CurveAffine, FieldExt};
use itertools::Itertools;
use std::{
	cmp::{max, Ordering},
	collections::{BTreeMap, BTreeSet},
	fmt::Debug,
	iter::{self, Sum},
	ops::{Add, Mul, Neg, Sub},
};

#[derive(Clone, Debug)]
pub struct Domain<F: FieldExt> {
	pub k: usize,
	pub n: usize,
	pub n_inv: F,
	pub gen: F,
	pub gen_inv: F,
}

impl<F: FieldExt> Domain<F> {
	pub fn new(k: usize) -> Self {
		assert!(k <= F::S as usize);

		let n = 1 << k;
		let n_inv = F::from(n as u64).invert().unwrap();
		let gen = iter::successors(Some(F::root_of_unity()), |acc| Some(acc.square()))
			.take(F::S as usize - k + 1)
			.last()
			.unwrap();
		let gen_inv = gen.invert().unwrap();

		Self { k, n, n_inv, gen, gen_inv }
	}

	pub fn rotate_scalar(&self, scalar: F, rotation: Rotation) -> F {
		match rotation.0.cmp(&0) {
			Ordering::Equal => scalar,
			Ordering::Greater => scalar * self.gen.pow_vartime(&[rotation.0 as u64]),
			Ordering::Less => scalar * self.gen_inv.pow_vartime(&[(-rotation.0) as u64]),
		}
	}
}

#[derive(Clone, Debug)]
pub struct Fraction<F: FieldExt> {
	numer: Option<F>,
	denom: F,
	inv: bool,
}

impl<F: FieldExt> Fraction<F> {
	pub fn new(numer: F, denom: F) -> Self {
		Self { numer: Some(numer), denom, inv: false }
	}

	pub fn one_over(denom: F) -> Self {
		Self { numer: None, denom, inv: false }
	}

	pub fn denom(&self) -> Option<&F> {
		if !self.inv {
			Some(&self.denom)
		} else {
			None
		}
	}

	pub fn denom_mut(&mut self) -> Option<&mut F> {
		if !self.inv {
			self.inv = true;
			Some(&mut self.denom)
		} else {
			None
		}
	}

	pub fn evaluate(&self) -> F {
		let denom = if self.inv { self.denom.clone() } else { self.denom.invert().unwrap() };
		self.numer.clone().map(|numer| numer * &denom).unwrap_or(denom)
	}
}

#[derive(Clone, Copy, Debug)]
pub enum CommonPolynomial {
	Identity,
	Lagrange(i32),
}

#[derive(Clone, Debug)]
pub struct CommonPolynomialEvaluation<F: FieldExt> {
	zn: F,
	zn_minus_one_inv: Fraction<F>,
	identity: F,
	lagrange: BTreeMap<i32, Fraction<F>>,
}

impl<F: FieldExt> CommonPolynomialEvaluation<F> {
	pub fn new(domain: &Domain<F>, langranges: impl IntoIterator<Item = i32>, z: F) -> Self {
		let zn = z.pow(&[domain.n as u64, 0, 0, 0]);
		let langranges = langranges.into_iter().sorted().dedup().collect_vec();

		let one = F::one();
		let zn_minus_one = zn.clone() - one;
		let numer = zn_minus_one.clone() * domain.n_inv;

		let omegas =
			langranges.iter().map(|&i| domain.rotate_scalar(F::one(), Rotation(i))).collect_vec();

		let lagrange_evals = omegas
			.iter()
			.map(|omega| Fraction::new(numer.clone() * omega, z.clone() - omega))
			.collect_vec();

		Self {
			zn,
			zn_minus_one_inv: Fraction::one_over(zn_minus_one),
			identity: z.clone(),
			lagrange: langranges.into_iter().zip(lagrange_evals).collect(),
		}
	}

	pub fn zn(&self) -> F {
		self.zn.clone()
	}

	pub fn zn_minus_one_inv(&self) -> F {
		self.zn_minus_one_inv.evaluate()
	}

	pub fn get(&self, poly: CommonPolynomial) -> F {
		match poly {
			CommonPolynomial::Identity => self.identity.clone(),
			CommonPolynomial::Lagrange(i) => self.lagrange.get(&i).unwrap().evaluate(),
		}
	}

	pub fn denoms(&mut self) -> impl IntoIterator<Item = &'_ mut F> {
		self.lagrange
			.iter_mut()
			.map(|(_, value)| value.denom_mut())
			.chain(iter::once(self.zn_minus_one_inv.denom_mut()))
			.flatten()
	}
}
