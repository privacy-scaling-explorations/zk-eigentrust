use crate::{
	ecc::{EccAddConfig, EccDoubleConfig, EccUnreducedLadderConfig},
	gadgets::main::MainConfig,
	CommonConfig,
};
use halo2::{
	arithmetic::Field,
	circuit::{AssignedCell, Layouter},
	halo2curves::FieldExt,
};
use snark_verifier::{
	loader::{EcPointLoader, LoadedEcPoint, LoadedScalar, Loader, ScalarLoader},
	util::arithmetic::{FieldOps, PrimeField},
	Error as VerifierError,
};
use std::{
	fmt::{Debug, Error, Formatter, Write},
	marker::PhantomData,
	ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
	rc::Rc,
};

#[derive(Clone)]
struct Halo2LoaderConfig {
	common: CommonConfig,
	main_config: MainConfig,
	ecc_add_config: EccAddConfig,
	ecc_double_config: EccDoubleConfig,
	ecc_ladder_config: EccUnreducedLadderConfig,
}

struct Halo2ScalarLoader<F: Field, L: Layouter<F>> {
	layouter: Rc<L>,
	config: Halo2LoaderConfig,
	_f: PhantomData<F>,
}

impl<F: Field, L: Layouter<F>> Clone for Halo2ScalarLoader<F, L> {
	fn clone(&self) -> Self {
		Self { layouter: self.layouter.clone(), config: self.config.clone(), _f: PhantomData }
	}
}

struct AssignedScalar<F: Field, L: Layouter<F>> {
	inner: AssignedCell<F, F>,
	loader: Halo2ScalarLoader<F, L>,
}

impl<F: Field, L: Layouter<F>> Clone for AssignedScalar<F, L> {
	fn clone(&self) -> Self {
		Self { inner: self.inner.clone(), loader: self.loader.clone() }
	}
}

impl<F: Field, L: Layouter<F>> Debug for AssignedScalar<F, L> {
	fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
		self.inner.fmt(f)?;
		Ok(())
	}
}

impl<F: Field, L: Layouter<F>> PartialEq for AssignedScalar<F, L> {
	fn eq(&self, other: &AssignedScalar<F, L>) -> bool {
		false
	}
}

impl<F: Field, L: Layouter<F>> AssignedScalar<F, L> {
	pub fn new(cell: AssignedCell<F, F>, loader: Halo2ScalarLoader<F, L>) -> Self {
		Self { inner: cell, loader }
	}
}

impl<F: Field, L: Layouter<F>> FieldOps for AssignedScalar<F, L> {
	fn invert(&self) -> Option<Self> {
		// TODO: InvertChip, TIP: Extract from MainGate.IsZeroChipset
		None
	}
}

// ---- ADD ----

impl<'a, F: Field, L: Layouter<F>> Add<&'a AssignedScalar<F, L>> for AssignedScalar<F, L> {
	type Output = AssignedScalar<F, L>;

	fn add(self, rhs: &'a AssignedScalar<F, L>) -> Self::Output {
		// TODO: AddChip
		self
	}
}

impl<F: Field, L: Layouter<F>> Add<AssignedScalar<F, L>> for AssignedScalar<F, L> {
	type Output = AssignedScalar<F, L>;

	fn add(self, rhs: AssignedScalar<F, L>) -> Self::Output {
		// TODO: AddChip -- reuse from above: add(self, rhs: &'a other)
		self
	}
}

impl<'a, F: Field, L: Layouter<F>> AddAssign<&'a AssignedScalar<F, L>> for AssignedScalar<F, L> {
	fn add_assign(&mut self, rhs: &'a AssignedScalar<F, L>) {
		// TODO: AddChip -- reuse from above: add(self, rhs: &'a other)
	}
}

impl<F: Field, L: Layouter<F>> AddAssign<AssignedScalar<F, L>> for AssignedScalar<F, L> {
	fn add_assign(&mut self, rhs: AssignedScalar<F, L>) {
		// TODO: AddChip -- reuse from above: add(self, rhs: &'a other)
	}
}

// ---- MUL ----

impl<'a, F: Field, L: Layouter<F>> Mul<&'a AssignedScalar<F, L>> for AssignedScalar<F, L> {
	type Output = AssignedScalar<F, L>;

	fn mul(self, rhs: &'a AssignedScalar<F, L>) -> Self::Output {
		// TODO: MulChip
		self
	}
}

impl<F: Field, L: Layouter<F>> Mul<AssignedScalar<F, L>> for AssignedScalar<F, L> {
	type Output = AssignedScalar<F, L>;

	fn mul(self, rhs: AssignedScalar<F, L>) -> Self::Output {
		// TODO: MulChip -- reuse from above: mul(self, rhs: &'a other)
		self
	}
}

impl<'a, F: Field, L: Layouter<F>> MulAssign<&'a AssignedScalar<F, L>> for AssignedScalar<F, L> {
	fn mul_assign(&mut self, rhs: &'a AssignedScalar<F, L>) {
		// TODO: MulChip -- reuse from above: mul(self, rhs: &'a other)
	}
}

impl<F: Field, L: Layouter<F>> MulAssign<AssignedScalar<F, L>> for AssignedScalar<F, L> {
	fn mul_assign(&mut self, rhs: AssignedScalar<F, L>) {
		// TODO: MulChip -- reuse from above: mul(self, rhs: &'a other)
	}
}

// ---- SUB ----

impl<'a, F: Field, L: Layouter<F>> Sub<&'a AssignedScalar<F, L>> for AssignedScalar<F, L> {
	type Output = AssignedScalar<F, L>;

	fn sub(self, rhs: &'a AssignedScalar<F, L>) -> Self::Output {
		// TODO: SubChip
		self
	}
}

impl<F: Field, L: Layouter<F>> Sub<AssignedScalar<F, L>> for AssignedScalar<F, L> {
	type Output = AssignedScalar<F, L>;

	fn sub(self, rhs: AssignedScalar<F, L>) -> Self::Output {
		// TODO: SubChip -- reuse from above: sub(self, rhs: &'a other)
		self
	}
}

impl<'a, F: Field, L: Layouter<F>> SubAssign<&'a AssignedScalar<F, L>> for AssignedScalar<F, L> {
	fn sub_assign(&mut self, rhs: &'a AssignedScalar<F, L>) {
		// TODO: SubChip -- reuse from above: sub(self, rhs: &'a other)
	}
}

impl<F: Field, L: Layouter<F>> SubAssign<AssignedScalar<F, L>> for AssignedScalar<F, L> {
	fn sub_assign(&mut self, rhs: AssignedScalar<F, L>) {
		// TODO: SubChip -- reuse from above: sub(self, rhs: &'a other)
	}
}

// ---- NEG ----

impl<F: Field, L: Layouter<F>> Neg for AssignedScalar<F, L> {
	type Output = Self;

	fn neg(self) -> Self::Output {
		// TODO: MulChip: multiplication with -1
		self
	}
}

// impl<F: FieldExt, L: Layouter<F>> LoadedScalar<F> for AssignedScalar<F, L> {
// 	/// [`Loader`].
// 	type Loader = Halo2ScalarLoader<F, L>;

// 	/// Returns [`Loader`].
// 	fn loader(&self) -> &Self::Loader {
// 		&self.loader
// 	}
// }

// impl<F: FieldExt, L: Layouter<F>> ScalarLoader<F> for Halo2ScalarLoader<F, L>
// { 	/// [`LoadedScalar`].
// 	type LoadedScalar = AssignedScalar<F, L>;

// 	/// Load a constant field element.
// 	fn load_const(&self, value: &F) -> Self::LoadedScalar {
// 		// TODO: Assign a value inside a new region and constrain it to be eq to
// 		// constant
// 	}

// 	/// Assert lhs and rhs field elements are equal.
// 	fn assert_eq(
// 		&self, annotation: &str, lhs: &Self::LoadedScalar, rhs: &Self::LoadedScalar,
// 	) -> Result<(), VerifierError> {
// 		Ok(())
// 	}
// }
