use crate::{
	ecc::{AssignedPoint, EccAddChipset, EccMulChipset, EccMulConfig},
	gadgets::main::{AddChipset, InverseChipset, MainConfig, MulChipset, SubChipset},
	integer::{native::Integer, rns::RnsParams, AssignedInteger},
	poseidon::sponge::PoseidonSpongeConfig,
	utils::assigned_to_field,
	Chipset, CommonConfig, RegionCtx,
};
use halo2::{
	circuit::{AssignedCell, Layouter, Region},
	halo2curves::{Coordinates, CurveAffine},
};
use native::{NUM_BITS, NUM_LIMBS};
use snark_verifier::{
	loader::{EcPointLoader, LoadedEcPoint, LoadedScalar, Loader, ScalarLoader},
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

/// LoaderConfig structure
pub struct LoaderConfig<C: CurveAffine, L: Layouter<C::Scalar>, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	// Layouter
	pub(crate) layouter: Rc<Mutex<L>>,
	// Configurations for the needed circuit configs.
	pub(crate) common: CommonConfig,
	pub(crate) ecc_mul_scalar: EccMulConfig,
	pub(crate) main: MainConfig,
	pub(crate) poseidon_sponge: PoseidonSpongeConfig,
	// Aux_init and Aux_fin for the ecc_mul operation
	pub(crate) auxes: (
		AssignedPoint<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS, P>,
		AssignedPoint<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS, P>,
	),
	// PhantomData
	_curve: PhantomData<C>,
	_p: PhantomData<P>,
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> LoaderConfig<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Construct a new LoaderConfig
	pub fn new(
		layouter: Rc<Mutex<L>>, common: CommonConfig, ecc_mul_scalar: EccMulConfig,
		main: MainConfig, poseidon_sponge: PoseidonSpongeConfig,
	) -> Self {
		let binding = layouter.clone();
		let mut layouter_reg = binding.lock().unwrap();
		let (aux_init_x_limbs, aux_init_y_limbs, aux_fin_x_limbs, aux_fin_y_limbs) = layouter_reg
			.assign_region(
				|| "aux",
				|region: Region<'_, C::Scalar>| {
					let mut ctx = RegionCtx::new(region, 0);
					let mut init_x_limbs: [Option<AssignedCell<C::Scalar, C::Scalar>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					let mut init_y_limbs: [Option<AssignedCell<C::Scalar, C::Scalar>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					for i in 0..NUM_LIMBS {
						let x = ctx.assign_fixed(common.fixed[i], P::to_add_x()[i])?;
						init_x_limbs[i] = Some(x);
					}
					ctx.next();
					for i in 0..NUM_LIMBS {
						let y = ctx.assign_fixed(common.fixed[i], P::to_add_y()[i])?;
						init_y_limbs[i] = Some(y);
					}

					ctx.next();
					let mut fin_x_limbs: [Option<AssignedCell<C::Scalar, C::Scalar>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					let mut fin_y_limbs: [Option<AssignedCell<C::Scalar, C::Scalar>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					for i in 0..NUM_LIMBS {
						let x = ctx.assign_fixed(common.fixed[i], P::to_sub_x()[i])?;

						fin_x_limbs[i] = Some(x);
					}
					ctx.next();
					for i in 0..NUM_LIMBS {
						let y = ctx.assign_fixed(common.fixed[i], P::to_sub_y()[i])?;
						fin_y_limbs[i] = Some(y);
					}

					Ok((
						init_x_limbs.map(|x| x.unwrap()),
						init_y_limbs.map(|x| x.unwrap()),
						fin_x_limbs.map(|x| x.unwrap()),
						fin_y_limbs.map(|x| x.unwrap()),
					))
				},
			)
			.unwrap();

		let aux_init_x_int =
			Integer::<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS, P>::from_limbs(P::to_add_x());
		let aux_init_y_int =
			Integer::<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS, P>::from_limbs(P::to_add_y());
		let aux_init_x = AssignedInteger::new(aux_init_x_int, aux_init_x_limbs);
		let aux_init_y = AssignedInteger::new(aux_init_y_int, aux_init_y_limbs);
		let aux_init = AssignedPoint::new(aux_init_x, aux_init_y);

		let aux_fin_x_int =
			Integer::<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS, P>::from_limbs(P::to_sub_x());
		let aux_fin_y_int =
			Integer::<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS, P>::from_limbs(P::to_sub_y());
		let aux_fin_x = AssignedInteger::new(aux_fin_x_int, aux_fin_x_limbs);
		let aux_fin_y = AssignedInteger::new(aux_fin_y_int, aux_fin_y_limbs);
		let aux_fin = AssignedPoint::new(aux_fin_x, aux_fin_y);
		let auxes = (aux_init, aux_fin);
		Self {
			layouter,
			common,
			ecc_mul_scalar,
			main,
			poseidon_sponge,
			auxes,
			_curve: PhantomData,
			_p: PhantomData,
		}
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Clone for LoaderConfig<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Returns a copy of the value.
	fn clone(&self) -> Self {
		Self {
			layouter: self.layouter.clone(),
			common: self.common.clone(),
			ecc_mul_scalar: self.ecc_mul_scalar.clone(),
			main: self.main.clone(),
			poseidon_sponge: self.poseidon_sponge.clone(),
			auxes: self.auxes.clone(),
			_curve: PhantomData,
			_p: PhantomData,
		}
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Debug for LoaderConfig<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Formats the value using the given formatter.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("LoaderConfig").finish()
	}
}

/// Halo2LScalar structure
pub struct Halo2LScalar<C: CurveAffine, L: Layouter<C::Scalar>, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	// Inner value for the halo2 loaded scalar
	pub(crate) inner: AssignedCell<C::Scalar, C::Scalar>,
	// Loader
	pub(crate) loader: LoaderConfig<C, L, P>,
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Creates a new Halo2LScalar
	pub fn new(value: AssignedCell<C::Scalar, C::Scalar>, loader: LoaderConfig<C, L, P>) -> Self {
		return Self { inner: value, loader };
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Clone for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Returns a copy of the value.
	fn clone(&self) -> Self {
		Self { inner: self.inner.clone(), loader: self.loader.clone() }
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Debug for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Formats the value using the given formatter.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Halo2LScalar").field("inner", &self.inner).finish()
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> PartialEq for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	///  This method tests for `self` and `other` values to be equal, and is
	/// used by `==`.
	fn eq(&self, other: &Self) -> bool {
		let lhs = assigned_to_field(self.inner.clone());
		let rhs = assigned_to_field(other.inner.clone());

		lhs == rhs
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> FieldOps for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Returns multiplicative inversion if any.
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

	/// Performs the `+` operation.
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

	/// Performs the `+` operation.
	fn add(self, rhs: Self) -> Self {
		self.add(&rhs)
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> AddAssign<&'a Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Performs the `+=` operation.
	fn add_assign(&mut self, rhs: &'a Self) {
		*self = self.clone().add(rhs);
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> AddAssign<Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Performs the `+=` operation.
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

	/// Performs the `*` operation.
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

	/// Performs the `*` operation.
	fn mul(self, rhs: Self) -> Self {
		self.mul(&rhs)
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> MulAssign<&'a Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Performs the `*=` operation.
	fn mul_assign(&mut self, rhs: &'a Self) {
		*self = self.clone().mul(rhs);
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> MulAssign<Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Performs the `*=` operation.
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

	/// Performs the `-` operation.
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

	/// Performs the `-` operation.
	fn sub(self, rhs: Self) -> Self {
		self.sub(&rhs)
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> SubAssign<&'a Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Performs the `-=` operation.
	fn sub_assign(&mut self, rhs: &'a Self) {
		*self = self.clone().sub(rhs);
	}
}

impl<'a, C: CurveAffine, L: Layouter<C::Scalar>, P> SubAssign<Self> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Performs the `-=` operation.
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

	/// Performs the unary `-` operation.
	fn neg(self) -> Self {
		let mut loader_ref = self.loader.layouter.lock().unwrap();
		let sub_chipset = SubChipset::new(self.inner.clone(), self.inner.clone());
		let zero = sub_chipset
			.synthesize(
				&self.loader.common,
				&self.loader.main,
				loader_ref.namespace(|| "loader_zero"),
			)
			.unwrap();
		let sub_chipset = SubChipset::new(zero, self.inner);
		let neg = sub_chipset
			.synthesize(
				&self.loader.common,
				&self.loader.main,
				loader_ref.namespace(|| "loader_neg"),
			)
			.unwrap();
		Self { inner: neg, loader: self.loader.clone() }
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> LoadedScalar<C::Scalar> for Halo2LScalar<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Loader = LoaderConfig<C, L, P>;

	/// Returns [`Loader`].
	fn loader(&self) -> &Self::Loader {
		&self.loader
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> ScalarLoader<C::Scalar> for LoaderConfig<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type LoadedScalar = Halo2LScalar<C, L, P>;

	/// Load a constant field element.
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

	/// Assert `lhs` and `rhs` field elements are equal.
	fn assert_eq(
		&self, annotation: &str, lhs: &Self::LoadedScalar, rhs: &Self::LoadedScalar,
	) -> Result<(), snark_verifier::Error> {
		let mut layouter = self.layouter.lock().unwrap();
		layouter
			.assign_region(
				|| "assert_eq",
				|region: Region<'_, C::Scalar>| {
					let mut ctx = RegionCtx::new(region, 0);
					let eq = ctx.constrain_equal(lhs.inner.clone(), rhs.inner.clone())?;
					Ok(eq)
				},
			)
			.ok()
			.ok_or_else(|| AssertionFailure(annotation.to_string()))
	}
}

/// Halo2LEcPoint structure
pub struct Halo2LEcPoint<C: CurveAffine, L: Layouter<C::Scalar>, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	// Inner value for the halo2 loaded point
	pub(crate) inner: AssignedPoint<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS, P>,
	// Loader
	pub(crate) loader: LoaderConfig<C, L, P>,
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Halo2LEcPoint<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Creates a new Halo2LScalar
	pub fn new(
		value: AssignedPoint<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS, P>,
		loader: LoaderConfig<C, L, P>,
	) -> Self {
		return Self { inner: value, loader };
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Clone for Halo2LEcPoint<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Returns a copy of the value.
	fn clone(&self) -> Self {
		Self { inner: self.inner.clone(), loader: self.loader.clone() }
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Debug for Halo2LEcPoint<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// Formats the value using the given formatter.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Halo2LEcPoint").field("inner", &self.inner).finish()
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> PartialEq for Halo2LEcPoint<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	/// This method tests for `self` and `other` values to be equal, and is used
	/// by `==`.
	fn eq(&self, other: &Self) -> bool {
		self.inner.x.integer == other.inner.x.integer
			&& self.inner.y.integer == other.inner.y.integer
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> LoadedEcPoint<C> for Halo2LEcPoint<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type Loader = LoaderConfig<C, L, P>;

	/// Returns [`Loader`].
	fn loader(&self) -> &Self::Loader {
		&self.loader
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> EcPointLoader<C> for LoaderConfig<C, L, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	type LoadedEcPoint = Halo2LEcPoint<C, L, P>;

	/// Load a constant elliptic curve point.
	fn ec_point_load_const(&self, value: &C) -> Self::LoadedEcPoint {
		let coords: Coordinates<C> = Option::from(value.coordinates()).unwrap();
		let x = Integer::from_w(coords.x().clone());
		let y = Integer::from_w(coords.y().clone());
		let mut layouter = self.layouter.lock().unwrap();
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

		let assigned_point = AssignedPoint::new(x_assigned, y_assigned);
		Halo2LEcPoint::new(assigned_point, self.clone())
	}

	/// Assert lhs and rhs elliptic curve points are equal.
	fn ec_point_assert_eq(
		&self, annotation: &str, lhs: &Self::LoadedEcPoint, rhs: &Self::LoadedEcPoint,
	) -> Result<(), snark_verifier::Error> {
		let mut layouter = self.layouter.lock().unwrap();
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
		// TODO: Define config and aux inside the iteratior
		let config = pairs[0].1.loader.clone();
		let auxes = pairs[0].1.loader.auxes.clone();
		let (aux_init, aux_fin) = auxes;
		let point = pairs
			.iter()
			.cloned()
			.map(|(scalar, base)| {
				// TODO: program stucks here somehow, try to fix it.
				let mut layouter = base.loader.layouter.lock().unwrap();
				let chip = EccMulChipset::new(
					base.inner.clone(),
					scalar.inner.clone(),
					aux_init.clone(),
					aux_fin.clone(),
				);
				let mul = chip
					.synthesize(
						&config.common,
						&config.ecc_mul_scalar,
						layouter.namespace(|| "ecc_mul"),
					)
					.unwrap();
				Halo2LEcPoint::new(mul, config.clone())
			})
			.reduce(|acc, value| {
				let mut layouter = value.loader.layouter.lock().unwrap();
				let chip = EccAddChipset::new(acc.inner.clone(), value.inner.clone());
				let add = chip
					.synthesize(
						&config.common,
						&config.ecc_mul_scalar.add,
						layouter.namespace(|| "ecc_add"),
					)
					.unwrap();
				Halo2LEcPoint::new(add, config.clone())
			})
			.unwrap();
		point
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Loader<C> for LoaderConfig<C, L, P> where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>
{
}

#[cfg(test)]
mod test {
	use super::{
		native::{LEcPoint, LScalar, NativeLoader, NUM_BITS, NUM_LIMBS},
		Halo2LEcPoint, Halo2LScalar, LoaderConfig,
	};
	use crate::{
		circuit::{FullRoundHasher, PartialRoundHasher},
		ecc::{
			native::EcPoint, AssignedPoint, EccAddConfig, EccDoubleConfig, EccMulConfig,
			EccTableSelectConfig, EccUnreducedLadderConfig,
		},
		gadgets::{
			absorb::AbsorbChip,
			bits2num::Bits2NumChip,
			main::{MainChip, MainConfig},
		},
		integer::{
			native::Integer, rns::Bn256_4_68, AssignedInteger, IntegerAddChip, IntegerDivChip,
			IntegerMulChip, IntegerReduceChip, IntegerSubChip,
		},
		poseidon::{sponge::PoseidonSpongeConfig, PoseidonConfig},
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
	use snark_verifier::loader::EcPointLoader;
	use std::{rc::Rc, sync::Mutex};

	type C = G1Affine;
	type P = Bn256_4_68;
	type Scalar = Fr;
	type Base = Fq;
	#[derive(Clone)]
	struct TestConfig {
		common: CommonConfig,
		main: MainConfig,
		poseidon_sponge: PoseidonSpongeConfig,
		ecc_mul_scalar: EccMulConfig,
	}

	#[derive(Clone)]
	struct TestCircuit {
		pairs: Vec<(LScalar<C, P>, LEcPoint<C, P>)>,
	}

	impl TestCircuit {
		fn new(pairs: Vec<(LScalar<C, P>, LEcPoint<C, P>)>) -> Self {
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
			let common = CommonConfig::new(meta);
			let main_selector = MainChip::configure(&common, meta);
			let main = MainConfig::new(main_selector);

			let full_round_selector = FullRoundHasher::configure(&common, meta);
			let partial_round_selector = PartialRoundHasher::configure(&common, meta);
			let poseidon = PoseidonConfig::new(full_round_selector, partial_round_selector);

			let absorb_selector = AbsorbChip::<Scalar, WIDTH>::configure(&common, meta);
			let poseidon_sponge = PoseidonSpongeConfig::new(poseidon.clone(), absorb_selector);

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
			let ecc_mul_scalar = EccMulConfig::new(ladder, add, double, table_select, bits2num);
			TestConfig { common, main, poseidon_sponge, ecc_mul_scalar }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Scalar>,
		) -> Result<(), Error> {
			let layouter_rc = Rc::new(Mutex::new(layouter.namespace(|| "loader")));
			let loader_config = LoaderConfig::<C, _, P>::new(
				layouter_rc.clone(),
				config.common.clone(),
				config.ecc_mul_scalar,
				config.main,
				config.poseidon_sponge,
			);

			let mut assigned_pairs: Vec<(Halo2LScalar<C, _, P>, Halo2LEcPoint<C, _, P>)> =
				Vec::new();
			let mut lb = layouter_rc.lock().unwrap();
			lb.assign_region(
				|| "assign_pairs",
				|region: Region<'_, Scalar>| {
					let mut ctx = RegionCtx::new(region, 0);
					for i in 0..self.pairs.len() {
						let assigned_scalar = ctx.assign_advice(
							config.common.advice[0],
							Value::known(self.pairs[i].0.inner),
						)?;
						ctx.next();
						let halo2_scalar =
							Halo2LScalar::new(assigned_scalar, loader_config.clone());

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

						let x = AssignedInteger::new(self.pairs[i].1.inner.x.clone(), x_limbs);
						let y = AssignedInteger::new(self.pairs[i].1.inner.y.clone(), y_limbs);

						let assigned_point = AssignedPoint::new(x, y);
						let halo2_point = Halo2LEcPoint::new(assigned_point, loader_config.clone());
						assigned_pairs.push((halo2_scalar, halo2_point));
					}
					Ok(())
				},
			)?;

			let borrowed_pairs: Vec<(&Halo2LScalar<C, _, P>, &Halo2LEcPoint<C, _, P>)> =
				assigned_pairs.iter().map(|x| (&x.0, &x.1)).collect();
			let res = LoaderConfig::multi_scalar_multiplication(borrowed_pairs.as_slice());

			for i in 0..NUM_LIMBS {
				lb.constrain_instance(
					res.inner.clone().x.limbs[i].cell(),
					config.common.instance,
					i,
				)?;
				lb.constrain_instance(
					res.inner.clone().y.limbs[i].cell(),
					config.common.instance,
					i + NUM_LIMBS,
				)?;
			}

			Ok(())
		}
	}

	#[ignore = "Stuck infinitely in MSM circuit."]
	#[test]
	fn test_multi_scalar_multiplication() {
		// Testing MSM
		let rng = &mut thread_rng();
		let loader = NativeLoader::<C, P>::new();
		let mut pairs: Vec<(LScalar<C, P>, LEcPoint<C, P>)> = Vec::new();
		for _ in 0..3 {
			let x = Integer::<Base, Scalar, NUM_LIMBS, NUM_BITS, P>::from_n(Scalar::random(
				rng.clone(),
			));
			let y = Integer::<Base, Scalar, NUM_LIMBS, NUM_BITS, P>::from_n(Scalar::random(
				rng.clone(),
			));
			let points = EcPoint::new(x, y);
			let scalar = LScalar::new(Scalar::random(rng.clone()), loader.clone());
			let ec_point = LEcPoint::new(points, loader.clone());
			pairs.push((scalar, ec_point));
		}
		let borrowed_pairs: Vec<(&LScalar<C, P>, &LEcPoint<C, P>)> =
			pairs.iter().map(|x| (&x.0, &x.1)).collect();
		let res = NativeLoader::multi_scalar_multiplication(borrowed_pairs.as_slice());

		let mut p_ins = Vec::new();
		p_ins.extend(res.inner.x.limbs);
		p_ins.extend(res.inner.y.limbs);
		let circuit = TestCircuit::new(pairs);
		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![p_ins]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}
}
