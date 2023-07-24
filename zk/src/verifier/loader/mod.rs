use crate::{
	ecc::{
		same_curve::{AssignedAux, AssignedEcPoint, AuxAssigner, EccAddChipset, EccMulChipset},
		AuxConfig, EccMulConfig,
	},
	gadgets::main::{AddChipset, InverseChipset, MainConfig, MulChipset, SubChipset},
	integer::{native::Integer, AssignedInteger},
	params::{ecc::EccParams, rns::RnsParams},
	utils::assigned_to_field,
	Chipset, CommonConfig, FieldExt, RegionCtx, SpongeHasherChipset,
};
use halo2::{
	circuit::{AssignedCell, Layouter, NamespacedLayouter, Region},
	halo2curves::{Coordinates, CurveAffine},
};
use native::{NUM_BITS, NUM_LIMBS};
use snark_verifier::{
	loader::{EcPointLoader, LoadedEcPoint, LoadedScalar, Loader, ScalarLoader},
	util::arithmetic::FieldOps,
	Error::AssertionFailure,
};
use std::{
	cell::RefCell,
	fmt::Debug,
	marker::PhantomData,
	ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
	rc::Rc,
};

/// Native version of the loader
pub mod native;

/// LoaderConfig structure
pub struct LoaderConfig<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	// Layouter
	pub(crate) layouter: Rc<RefCell<NamespacedLayouter<'a, C::Scalar, L>>>,
	// Configurations for the needed circuit configs.
	pub(crate) common: CommonConfig,
	pub(crate) ecc_mul_scalar: EccMulConfig,
	pub(crate) main: MainConfig,
	pub(crate) sponge: H::Config,
	// Aux_init and Aux_fin for the ecc_mul operation
	pub(crate) aux: AssignedAux<C, NUM_LIMBS, NUM_BITS, P, EC>,
	// PhantomData
	_curve: PhantomData<C>,
	_p: PhantomData<P>,
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> LoaderConfig<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Construct a new LoaderConfig
	pub fn new(
		mut layouter: NamespacedLayouter<'a, C::Scalar, L>, common: CommonConfig,
		ecc_mul_scalar: EccMulConfig, aux_config: AuxConfig, main: MainConfig, sponge: H::Config,
	) -> Self {
		let aux_assigner = AuxAssigner::new();
		let aux = aux_assigner
			.synthesize(&common, &aux_config, layouter.namespace(|| "aux_assigner"))
			.unwrap();

		let layouter_rc = Rc::new(RefCell::new(layouter));
		Self {
			layouter: layouter_rc,
			common,
			ecc_mul_scalar,
			main,
			sponge,
			aux,
			_curve: PhantomData,
			_p: PhantomData,
		}
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> Clone
	for LoaderConfig<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Returns a copy of the value.
	fn clone(&self) -> Self {
		Self {
			layouter: self.layouter.clone(),
			common: self.common.clone(),
			ecc_mul_scalar: self.ecc_mul_scalar.clone(),
			main: self.main.clone(),
			sponge: self.sponge.clone(),
			aux: self.aux.clone(),
			_curve: PhantomData,
			_p: PhantomData,
		}
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> Debug
	for LoaderConfig<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Formats the value using the given formatter.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("LoaderConfig").finish()
	}
}

/// Halo2LScalar structure
pub struct Halo2LScalar<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	// Inner value for the halo2 loaded scalar
	pub(crate) inner: AssignedCell<C::Scalar, C::Scalar>,
	// Loader
	pub(crate) loader: LoaderConfig<'a, C, L, P, H, EC>,
	_h: PhantomData<H>,
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> Halo2LScalar<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Creates a new Halo2LScalar
	pub fn new(
		value: AssignedCell<C::Scalar, C::Scalar>, loader: LoaderConfig<'a, C, L, P, H, EC>,
	) -> Self {
		Self { inner: value, loader, _h: PhantomData }
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> Clone
	for Halo2LScalar<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Returns a copy of the value.
	fn clone(&self) -> Self {
		Self { inner: self.inner.clone(), loader: self.loader.clone(), _h: PhantomData }
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> Debug
	for Halo2LScalar<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Formats the value using the given formatter.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Halo2LScalar").field("inner", &self.inner).finish()
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> PartialEq
	for Halo2LScalar<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	///  This method tests for `self` and `other` values to be equal, and is
	/// used by `==`.
	fn eq(&self, other: &Self) -> bool {
		let lhs = assigned_to_field(self.inner.clone());
		let rhs = assigned_to_field(other.inner.clone());

		lhs == rhs
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> FieldOps
	for Halo2LScalar<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Returns multiplicative inversion if any.
	fn invert(&self) -> Option<Self> {
		let mut layouter_mut = self.loader.layouter.borrow_mut();
		let inv_chipset = InverseChipset::new(self.inner.clone());
		let inv_op = inv_chipset.synthesize(
			&self.loader.common,
			&self.loader.main,
			layouter_mut.namespace(|| "loader_inverse"),
		);
		inv_op.ok().map(|x| Self { inner: x, loader: self.loader.clone(), _h: PhantomData })
	}
}

// ---- ADD ----

impl<'a, 'b, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> Add<&'a Self>
	for Halo2LScalar<'b, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Output = Self;

	/// Performs the `+` operation.
	fn add(self, rhs: &'a Self) -> Self {
		let mut layouter_mut = self.loader.layouter.borrow_mut();
		let add_chipset = AddChipset::new(self.inner, rhs.inner.clone());
		let add = add_chipset
			.synthesize(
				&self.loader.common,
				&self.loader.main,
				layouter_mut.namespace(|| "loader_add"),
			)
			.unwrap();
		Self { inner: add, loader: self.loader.clone(), _h: PhantomData }
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> Add<Self>
	for Halo2LScalar<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Output = Self;

	/// Performs the `+` operation.
	fn add(self, rhs: Self) -> Self {
		self.add(&rhs)
	}
}

impl<'a, 'b, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> AddAssign<&'a Self>
	for Halo2LScalar<'b, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Performs the `+=` operation.
	fn add_assign(&mut self, rhs: &'a Self) {
		*self = self.clone().add(rhs);
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> AddAssign<Self>
	for Halo2LScalar<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Performs the `+=` operation.
	fn add_assign(&mut self, rhs: Self) {
		self.add_assign(&rhs)
	}
}

// ---- MUL ----

impl<'a, 'b, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> Mul<&'a Self>
	for Halo2LScalar<'b, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Output = Self;

	/// Performs the `*` operation.
	fn mul(self, rhs: &'a Self) -> Self {
		let mut layouter_mut = self.loader.layouter.borrow_mut();
		let mul_chipset = MulChipset::new(self.inner, rhs.inner.clone());
		let mul = mul_chipset
			.synthesize(
				&self.loader.common,
				&self.loader.main,
				layouter_mut.namespace(|| "loader_mul"),
			)
			.unwrap();
		Self { inner: mul, loader: self.loader.clone(), _h: PhantomData }
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> Mul<Self>
	for Halo2LScalar<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Output = Self;

	/// Performs the `*` operation.
	fn mul(self, rhs: Self) -> Self {
		self.mul(&rhs)
	}
}

impl<'a, 'b, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> MulAssign<&'a Self>
	for Halo2LScalar<'b, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Performs the `*=` operation.
	fn mul_assign(&mut self, rhs: &'a Self) {
		*self = self.clone().mul(rhs);
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> MulAssign<Self>
	for Halo2LScalar<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Performs the `*=` operation.
	fn mul_assign(&mut self, rhs: Self) {
		self.mul_assign(&rhs)
	}
}

// ---- SUB ----

impl<'a, 'b, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> Sub<&'a Self>
	for Halo2LScalar<'b, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Output = Self;

	/// Performs the `-` operation.
	fn sub(self, rhs: &'a Self) -> Self {
		let mut layouter_mut = self.loader.layouter.borrow_mut();
		let sub_chipset = SubChipset::new(self.inner, rhs.inner.clone());
		let sub = sub_chipset
			.synthesize(
				&self.loader.common,
				&self.loader.main,
				layouter_mut.namespace(|| "loader_sub"),
			)
			.unwrap();
		Self { inner: sub, loader: self.loader.clone(), _h: PhantomData }
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> Sub<Self>
	for Halo2LScalar<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Output = Self;

	/// Performs the `-` operation.
	fn sub(self, rhs: Self) -> Self {
		self.sub(&rhs)
	}
}

impl<'a, 'b, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> SubAssign<&'a Self>
	for Halo2LScalar<'b, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Performs the `-=` operation.
	fn sub_assign(&mut self, rhs: &'a Self) {
		*self = self.clone().sub(rhs);
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> SubAssign<Self>
	for Halo2LScalar<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Performs the `-=` operation.
	fn sub_assign(&mut self, rhs: Self) {
		self.sub_assign(&rhs)
	}
}

// ---- NEG ----

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> Neg for Halo2LScalar<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Output = Self;

	/// Performs the unary `-` operation.
	fn neg(self) -> Self {
		let mut layouter_mut = self.loader.layouter.borrow_mut();
		let sub_chipset = SubChipset::new(self.inner.clone(), self.inner.clone());
		let zero = sub_chipset
			.synthesize(
				&self.loader.common,
				&self.loader.main,
				layouter_mut.namespace(|| "loader_zero"),
			)
			.unwrap();
		let sub_chipset = SubChipset::new(zero, self.inner);
		let neg = sub_chipset
			.synthesize(
				&self.loader.common,
				&self.loader.main,
				layouter_mut.namespace(|| "loader_neg"),
			)
			.unwrap();
		Self { inner: neg, loader: self.loader.clone(), _h: PhantomData }
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> LoadedScalar<C::Scalar>
	for Halo2LScalar<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Loader = LoaderConfig<'a, C, L, P, H, EC>;

	/// Returns [`Loader`].
	fn loader(&self) -> &Self::Loader {
		&self.loader
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> ScalarLoader<C::Scalar>
	for LoaderConfig<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type LoadedScalar = Halo2LScalar<'a, C, L, P, H, EC>;

	/// Load a constant field element.
	fn load_const(&self, value: &C::Scalar) -> Self::LoadedScalar {
		let mut loader_mut = self.layouter.borrow_mut();
		let assigned_value = loader_mut
			.assign_region(
				|| "load_const",
				|region: Region<'_, C::Scalar>| {
					let mut ctx = RegionCtx::new(region, 0);
					ctx.assign_fixed(self.common.fixed[0], *value)
				},
			)
			.unwrap();

		Halo2LScalar::new(assigned_value, self.clone())
	}

	/// Assert `lhs` and `rhs` field elements are equal.
	fn assert_eq(
		&self, annotation: &str, lhs: &Self::LoadedScalar, rhs: &Self::LoadedScalar,
	) -> Result<(), snark_verifier::Error> {
		let mut loader_mut = self.layouter.borrow_mut();
		loader_mut
			.assign_region(
				|| "assert_eq",
				|region: Region<'_, C::Scalar>| {
					let mut ctx = RegionCtx::new(region, 0);
					ctx.constrain_equal(lhs.inner.clone(), rhs.inner.clone())?;
					Ok(())
				},
			)
			.ok()
			.ok_or_else(|| AssertionFailure(annotation.to_string()))
	}
}

/// Halo2LEcPoint structure
pub struct Halo2LEcPoint<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	// Inner value for the halo2 loaded point
	pub(crate) inner: AssignedEcPoint<C, NUM_LIMBS, NUM_BITS, P>,
	// Loader
	pub(crate) loader: LoaderConfig<'a, C, L, P, H, EC>,
	_h: PhantomData<H>,
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> Halo2LEcPoint<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Creates a new Halo2LScalar
	pub fn new(
		value: AssignedEcPoint<C, NUM_LIMBS, NUM_BITS, P>, loader: LoaderConfig<'a, C, L, P, H, EC>,
	) -> Self {
		Self { inner: value, loader, _h: PhantomData }
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> Clone
	for Halo2LEcPoint<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Returns a copy of the value.
	fn clone(&self) -> Self {
		Self { inner: self.inner.clone(), loader: self.loader.clone(), _h: PhantomData }
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> Debug
	for Halo2LEcPoint<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// Formats the value using the given formatter.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Halo2LEcPoint").field("inner", &self.inner).finish()
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> PartialEq
	for Halo2LEcPoint<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	/// This method tests for `self` and `other` values to be equal, and is used
	/// by `==`.
	fn eq(&self, other: &Self) -> bool {
		self.inner.x.integer == other.inner.x.integer
			&& self.inner.y.integer == other.inner.y.integer
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> LoadedEcPoint<C>
	for Halo2LEcPoint<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type Loader = LoaderConfig<'a, C, L, P, H, EC>;

	/// Returns [`Loader`].
	fn loader(&self) -> &Self::Loader {
		&self.loader
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> EcPointLoader<C>
	for LoaderConfig<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
	type LoadedEcPoint = Halo2LEcPoint<'a, C, L, P, H, EC>;

	/// Load a constant elliptic curve point.
	fn ec_point_load_const(&self, value: &C) -> Self::LoadedEcPoint {
		let coords: Coordinates<C> = Option::from(value.coordinates()).unwrap();
		let x = Integer::from_w(*coords.x());
		let y = Integer::from_w(*coords.y());
		let mut layouter = self.layouter.borrow_mut();
		let (x_limbs, y_limbs) = layouter
			.assign_region(
				|| "assign_limbs",
				|region: Region<'_, C::Scalar>| {
					let mut ctx = RegionCtx::new(region, 0);
					let mut x_limbs: [Option<AssignedCell<C::Scalar, C::Scalar>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					let mut y_limbs: [Option<AssignedCell<C::Scalar, C::Scalar>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					for i in 0..NUM_LIMBS {
						x_limbs[i] =
							Some(ctx.assign_fixed(self.common.fixed[i], x.limbs[i]).unwrap());
					}
					ctx.next();
					for i in 0..NUM_LIMBS {
						y_limbs[i] =
							Some(ctx.assign_fixed(self.common.fixed[i], y.limbs[i]).unwrap());
					}
					Ok((x_limbs.map(|x| x.unwrap()), y_limbs.map(|x| x.unwrap())))
				},
			)
			.unwrap();
		let x_assigned = AssignedInteger::new(x, x_limbs);
		let y_assigned = AssignedInteger::new(y, y_limbs);

		let assigned_point = AssignedEcPoint::new(x_assigned, y_assigned);
		Halo2LEcPoint::new(assigned_point, self.clone())
	}

	/// Assert lhs and rhs elliptic curve points are equal.
	fn ec_point_assert_eq(
		&self, annotation: &str, lhs: &Self::LoadedEcPoint, rhs: &Self::LoadedEcPoint,
	) -> Result<(), snark_verifier::Error> {
		let mut layouter = self.layouter.borrow_mut();
		layouter
			.assign_region(
				|| "assert_eq",
				|region: Region<'_, C::Scalar>| {
					let mut ctx = RegionCtx::new(region, 0);
					for i in 0..NUM_LIMBS {
						ctx.constrain_equal(
							lhs.inner.x.limbs[i].clone(),
							rhs.inner.x.limbs[i].clone(),
						)?;
						ctx.constrain_equal(
							lhs.inner.y.limbs[i].clone(),
							rhs.inner.y.limbs[i].clone(),
						)?;
					}
					Ok(())
				},
			)
			.map_err(|_| AssertionFailure(annotation.to_string()))
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
				let config = base.loader.clone();
				let aux = base.loader.aux.clone();

				let mut layouter = base.loader.layouter.borrow_mut();
				let chip = EccMulChipset::new(base.inner.clone(), scalar.inner.clone(), aux);
				let mul = chip
					.synthesize(
						&config.common,
						&config.ecc_mul_scalar,
						layouter.namespace(|| "ecc_mul"),
					)
					.unwrap();
				Halo2LEcPoint::new(mul, config)
			})
			.reduce(|acc, value| {
				let config = value.loader.clone();
				let mut layouter = value.loader.layouter.borrow_mut();
				let chip = EccAddChipset::new(acc.inner, value.inner.clone());
				let add = chip
					.synthesize(
						&config.common,
						&config.ecc_mul_scalar.add,
						layouter.namespace(|| "ecc_add"),
					)
					.unwrap();
				Halo2LEcPoint::new(add, config)
			})
			.unwrap();
		point
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P, H, EC> Loader<C>
	for LoaderConfig<'a, C, L, P, H, EC>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
	H: SpongeHasherChipset<C::Scalar>,
	EC: EccParams<C>,
	C::Base: FieldExt,
	C::Scalar: FieldExt,
{
}

#[cfg(test)]
mod test {
	use super::{
		native::{LEcPoint, LScalar, NativeLoader, NUM_BITS, NUM_LIMBS},
		Halo2LEcPoint, Halo2LScalar, LoaderConfig,
	};
	use crate::{
		circuits::{FullRoundHasher, PartialRoundHasher},
		ecc::{
			same_curve::{native::EcPoint, AssignedEcPoint},
			AuxConfig, EccAddConfig, EccDoubleConfig, EccMulConfig, EccTableSelectConfig,
			EccUnreducedLadderConfig,
		},
		gadgets::{
			absorb::AbsorbChip,
			bits2num::Bits2NumChip,
			main::{MainChip, MainConfig},
		},
		integer::{
			native::Integer, AssignedInteger, IntegerAddChip, IntegerDivChip, IntegerMulChip,
			IntegerReduceChip, IntegerSubChip,
		},
		params::hasher::poseidon_bn254_5x5::Params,
		params::{ecc::bn254::Bn254Params, rns::bn256::Bn256_4_68},
		poseidon::{
			sponge::{PoseidonSpongeConfig, StatefulSpongeChipset},
			PoseidonConfig,
		},
		verifier::transcript::native::WIDTH,
		Chip, CommonConfig, RegionCtx,
	};
	use halo2::{
		arithmetic::Field,
		circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::bn256::{Fq, Fr, G1Affine},
		plonk::{Circuit, ConstraintSystem, Error},
	};
	use rand::thread_rng;
	use snark_verifier::loader::{EcPointLoader, LoadedScalar};

	type C = G1Affine;
	type P = Bn256_4_68;
	type EC = Bn254Params;
	type H = StatefulSpongeChipset<Fr, 5, Params>;
	type Scalar = Fr;
	type Base = Fq;

	#[derive(Clone)]
	struct TestConfig {
		common: CommonConfig,
		main: MainConfig,
		poseidon_sponge: PoseidonSpongeConfig,
		ecc_mul_scalar: EccMulConfig,
		aux: AuxConfig,
	}

	impl TestConfig {
		fn new(meta: &mut ConstraintSystem<Scalar>) -> Self {
			let common = CommonConfig::new(meta);
			let main_selector = MainChip::configure(&common, meta);
			let main = MainConfig::new(main_selector);

			let full_round_selector = FullRoundHasher::configure(&common, meta);
			let partial_round_selector = PartialRoundHasher::configure(&common, meta);
			let poseidon = PoseidonConfig::new(full_round_selector, partial_round_selector);

			let absorb_selector = AbsorbChip::<Scalar, WIDTH>::configure(&common, meta);
			let poseidon_sponge = PoseidonSpongeConfig::new(poseidon, absorb_selector);

			let bits2num = Bits2NumChip::configure(&common, meta);

			let int_red =
				IntegerReduceChip::<Base, Scalar, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let int_add =
				IntegerAddChip::<Base, Scalar, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let int_sub =
				IntegerSubChip::<Base, Scalar, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let int_mul =
				IntegerMulChip::<Base, Scalar, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);
			let int_div =
				IntegerDivChip::<Base, Scalar, NUM_LIMBS, NUM_BITS, P>::configure(&common, meta);

			let ladder = EccUnreducedLadderConfig::new(int_add, int_sub, int_mul, int_div);
			let add = EccAddConfig::new(int_red, int_sub, int_mul, int_div);
			let double = EccDoubleConfig::new(int_red, int_add, int_sub, int_mul, int_div);
			let table_select = EccTableSelectConfig::new(main.clone());
			let ecc_mul_scalar =
				EccMulConfig::new(ladder, add, double.clone(), table_select, bits2num);
			let aux = AuxConfig::new(double);

			TestConfig { common, main, ecc_mul_scalar, poseidon_sponge, aux }
		}
	}

	#[derive(Clone)]
	struct TestLScalarInvertCircuit {
		x: Value<Scalar>,
	}

	impl TestLScalarInvertCircuit {
		fn new(x: Scalar) -> Self {
			Self { x: Value::known(x) }
		}
	}

	impl Circuit<Scalar> for TestLScalarInvertCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { x: Value::unknown() }
		}

		fn configure(meta: &mut ConstraintSystem<Scalar>) -> Self::Config {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: Self::Config, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let assigned_x = layouter.assign_region(
				|| "temp",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					let x = ctx.assign_advice(config.common.advice[0], self.x)?;
					Ok(x)
				},
			)?;
			let loader_config = LoaderConfig::<C, _, P, H, EC>::new(
				layouter.namespace(|| "loader_config"),
				config.common.clone(),
				config.ecc_mul_scalar,
				config.aux,
				config.main,
				config.poseidon_sponge,
			);

			let lscalar_x: Halo2LScalar<C, _, _, _, _> =
				Halo2LScalar::new(assigned_x, loader_config.clone());
			let inverted_lscalar_x = lscalar_x.invert().unwrap();

			loader_config.layouter.borrow_mut().constrain_instance(
				inverted_lscalar_x.inner.cell(),
				config.common.instance,
				0,
			)?;

			Ok(())
		}
	}

	#[test]
	fn test_halo2_lscalar_invert() {
		let x = Scalar::one() + Scalar::one();
		let inverted_x = LoadedScalar::invert(&x).unwrap();

		let k = 5;
		let circuit = TestLScalarInvertCircuit::new(x);
		let pub_ins = vec![inverted_x];

		let prover = MockProver::run(k, &circuit, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct TestLScalarAddCircuit {
		x: Value<Scalar>,
		y: Value<Scalar>,
	}

	impl TestLScalarAddCircuit {
		pub fn new(x: Scalar, y: Scalar) -> Self {
			Self { x: Value::known(x), y: Value::known(y) }
		}
	}

	impl Circuit<Scalar> for TestLScalarAddCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { x: Value::unknown(), y: Value::unknown() }
		}

		fn configure(meta: &mut ConstraintSystem<Scalar>) -> Self::Config {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: Self::Config, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let (assigned_x, assigned_y) = layouter.assign_region(
				|| "temp",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					let x = ctx.assign_advice(config.common.advice[0], self.x)?;
					let y = ctx.assign_advice(config.common.advice[1], self.y)?;
					Ok((x, y))
				},
			)?;
			let loader_config: LoaderConfig<C, _, P, H, EC> = LoaderConfig::new(
				layouter.namespace(|| "loader_config"),
				config.common.clone(),
				config.ecc_mul_scalar,
				config.aux,
				config.main,
				config.poseidon_sponge,
			);

			let lscalar_x = Halo2LScalar::new(assigned_x, loader_config.clone());
			let lscalar_y = Halo2LScalar::new(assigned_y, loader_config.clone());

			let lscalar_sum = lscalar_x + lscalar_y;

			loader_config.layouter.borrow_mut().constrain_instance(
				lscalar_sum.inner.cell(),
				config.common.instance,
				0,
			)?;

			Ok(())
		}
	}

	#[test]
	fn test_halo2_lscalar_add() {
		let x = Scalar::zero();
		let y = Scalar::one();
		let z = x + y;

		let k = 5;
		let circuit = TestLScalarAddCircuit::new(x, y);
		let pub_ins = vec![z];
		let prover = MockProver::run(k, &circuit, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct TestLScalarAddAssignCircuit {
		x: Value<Scalar>,
		y: Value<Scalar>,
	}

	impl TestLScalarAddAssignCircuit {
		pub fn new(x: Scalar, y: Scalar) -> Self {
			Self { x: Value::known(x), y: Value::known(y) }
		}
	}

	impl Circuit<Scalar> for TestLScalarAddAssignCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { x: Value::unknown(), y: Value::unknown() }
		}

		fn configure(meta: &mut ConstraintSystem<Scalar>) -> Self::Config {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: Self::Config, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let (assigned_x, assigned_y) = layouter.assign_region(
				|| "temp",
				|region| {
					let mut ctx = RegionCtx::new(region, 0);
					let x = ctx.assign_advice(config.common.advice[0], self.x)?;
					let y = ctx.assign_advice(config.common.advice[1], self.y)?;
					Ok((x, y))
				},
			)?;
			let loader_config: LoaderConfig<C, _, P, H, EC> = LoaderConfig::new(
				layouter.namespace(|| "loader_config"),
				config.common.clone(),
				config.ecc_mul_scalar,
				config.aux,
				config.main,
				config.poseidon_sponge,
			);

			let mut lscalar_x = Halo2LScalar::new(assigned_x, loader_config.clone());
			let lscalar_y = Halo2LScalar::new(assigned_y, loader_config.clone());

			lscalar_x += lscalar_y;

			loader_config.layouter.borrow_mut().constrain_instance(
				lscalar_x.inner.cell(),
				config.common.instance,
				0,
			)?;

			Ok(())
		}
	}

	#[test]
	fn test_halo2_lscalar_add_assign() {
		let mut x = Scalar::zero();
		let y = Scalar::one();

		let k = 5;
		let circuit = TestLScalarAddAssignCircuit::new(x, y);

		x += y;
		let pub_ins = vec![x];

		let prover = MockProver::run(k, &circuit, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct TestCircuit {
		pairs: Vec<(LScalar<C, P, EC>, LEcPoint<C, P, EC>)>,
	}

	impl TestCircuit {
		fn new(pairs: Vec<(LScalar<C, P, EC>, LEcPoint<C, P, EC>)>) -> Self {
			Self { pairs }
		}
	}

	impl Circuit<Scalar> for TestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<Scalar>) -> TestConfig {
			TestConfig::new(meta)
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let pairs = layouter.assign_region(
				|| "assign_pairs",
				|region: Region<'_, Scalar>| {
					let mut ctx = RegionCtx::new(region, 0);

					let mut pairs = Vec::new();
					for i in 0..self.pairs.len() {
						let assigned_scalar = ctx.assign_advice(
							config.common.advice[0],
							Value::known(self.pairs[i].0.inner),
						)?;
						ctx.next();

						let mut x_limbs: [Option<AssignedCell<Scalar, Scalar>>; NUM_LIMBS] =
							[(); NUM_LIMBS].map(|_| None);
						let mut y_limbs: [Option<AssignedCell<Scalar, Scalar>>; NUM_LIMBS] =
							[(); NUM_LIMBS].map(|_| None);
						for j in 0..NUM_LIMBS {
							x_limbs[j] = Some(ctx.assign_advice(
								config.common.advice[j],
								Value::known(self.pairs[i].1.inner.x.limbs[j]),
							)?);
							y_limbs[j] = Some(ctx.assign_advice(
								config.common.advice[j + NUM_LIMBS],
								Value::known(self.pairs[i].1.inner.y.limbs[j]),
							)?);
						}
						ctx.next();
						let x_limbs = x_limbs.map(|x| x.unwrap());
						let y_limbs = y_limbs.map(|x| x.unwrap());

						pairs.push((assigned_scalar, x_limbs, y_limbs));
					}
					Ok(pairs)
				},
			)?;

			let (x_limbs, y_limbs) = {
				let loader_config = LoaderConfig::<C, _, P, H, EC>::new(
					layouter.namespace(|| "loader"),
					config.common.clone(),
					config.ecc_mul_scalar,
					config.aux,
					config.main,
					config.poseidon_sponge,
				);

				let mut halo2_pairs = Vec::new();
				for (assigned_pair, nloaded_pair) in pairs.iter().zip(self.pairs.clone()) {
					let (scalar, x_limbs, y_limbs) = assigned_pair;
					let (_, lpoint) = nloaded_pair;
					let halo2_scalar = Halo2LScalar::new(scalar.clone(), loader_config.clone());

					let x = AssignedInteger::new(lpoint.inner.x.clone(), x_limbs.clone());
					let y = AssignedInteger::new(lpoint.inner.y.clone(), y_limbs.clone());

					let assigned_point = AssignedEcPoint::new(x, y);
					let halo2_point = Halo2LEcPoint::new(assigned_point, loader_config.clone());

					halo2_pairs.push((halo2_scalar, halo2_point));
				}

				let borrowed_pairs: Vec<(
					&Halo2LScalar<C, _, P, H, EC>,
					&Halo2LEcPoint<C, _, P, H, EC>,
				)> = halo2_pairs.iter().map(|x| (&x.0, &x.1)).collect();

				let res = LoaderConfig::multi_scalar_multiplication(borrowed_pairs.as_slice());

				let x_limbs = res.inner.x.limbs;
				let y_limbs = res.inner.y.limbs;

				(x_limbs, y_limbs)
			};

			for i in 0..NUM_LIMBS {
				layouter.constrain_instance(x_limbs[i].cell(), config.common.instance, i)?;
				layouter.constrain_instance(
					y_limbs[i].cell(),
					config.common.instance,
					i + NUM_LIMBS,
				)?;
			}

			Ok(())
		}
	}

	#[test]
	fn test_multi_scalar_multiplication() {
		// Testing MSM
		let rng = &mut thread_rng();
		let loader = NativeLoader::<C, P, EC>::new();
		let mut pairs: Vec<(LScalar<C, P, EC>, LEcPoint<C, P, EC>)> = Vec::new();
		for _ in 0..3 {
			let x = Integer::<Base, Scalar, NUM_LIMBS, NUM_BITS, P>::from_n(Scalar::random(
				rng.clone(),
			));
			let y = Integer::<Base, Scalar, NUM_LIMBS, NUM_BITS, P>::from_n(Scalar::random(
				rng.clone(),
			));
			let points = EcPoint::new(x, y);
			let ec_point = LEcPoint::new(points, loader.clone());
			let scalar = LScalar::new(Scalar::random(rng.clone()), loader.clone());

			pairs.push((scalar, ec_point));
		}
		let borrowed_pairs: Vec<(&LScalar<C, P, EC>, &LEcPoint<C, P, EC>)> =
			pairs.iter().map(|x| (&x.0, &x.1)).collect();
		let res = NativeLoader::multi_scalar_multiplication(borrowed_pairs.as_slice());

		let mut p_ins = Vec::new();
		p_ins.extend(res.inner.x.limbs);
		p_ins.extend(res.inner.y.limbs);
		let circuit = TestCircuit::new(pairs);
		let k = 16;
		let prover = MockProver::run(k, &circuit, vec![p_ins]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}
}
