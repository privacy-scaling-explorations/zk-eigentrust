use crate::{
	ecc::{AssignedPoint, EccAddChipset, EccMulChipset, EccMulConfig},
	gadgets::main::{AddChipset, InverseChipset, MainConfig, MulChipset, SubChipset},
	integer::{native::Integer, rns::RnsParams, AssignedInteger},
	poseidon::sponge::PoseidonSpongeConfig,
	utils::assigned_to_field,
	Chipset, CommonConfig, RegionCtx,
};
use halo2::{
	circuit::{AssignedCell, Layouter, Region, Value},
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

/// LoaderConfig
pub struct LoaderConfig<C: CurveAffine, L: Layouter<C::Scalar>, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	pub(crate) layouter: Rc<Mutex<L>>,
	pub(crate) common: CommonConfig,
	pub(crate) ecc_mul_scalar: EccMulConfig,
	pub(crate) main: MainConfig,
	pub(crate) poseidon_sponge: PoseidonSpongeConfig,
	pub(crate) auxes: (
		AssignedPoint<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS, P>,
		AssignedPoint<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS, P>,
	),
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
						let x =
							ctx.assign_advice(common.advice[i], Value::known(P::to_add_x()[i]))?;
						let y = ctx.assign_advice(
							common.advice[i + NUM_LIMBS],
							Value::known(P::to_add_y()[i]),
						)?;
						init_x_limbs[i] = Some(x);
						init_y_limbs[i] = Some(y);
					}

					ctx.next();
					let mut fin_x_limbs: [Option<AssignedCell<C::Scalar, C::Scalar>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					let mut fin_y_limbs: [Option<AssignedCell<C::Scalar, C::Scalar>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					for i in 0..NUM_LIMBS {
						let x =
							ctx.assign_advice(common.advice[i], Value::known(P::to_sub_x()[i]))?;
						let y = ctx.assign_advice(
							common.advice[i + NUM_LIMBS],
							Value::known(P::to_sub_y()[i]),
						)?;

						fin_x_limbs[i] = Some(x);
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
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("LoaderConfig").finish()
	}
}

/// Halo2 loaded scalar structure
pub struct Halo2LScalar<C: CurveAffine, L: Layouter<C::Scalar>, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	pub(crate) inner: AssignedCell<C::Scalar, C::Scalar>,
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
		let lhs = assigned_to_field(self.inner.clone());
		let rhs = assigned_to_field(other.inner.clone());

		lhs == rhs
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

/// Halo2 loaded ec point structure
pub struct Halo2LEcPoint<C: CurveAffine, L: Layouter<C::Scalar>, P>
where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>,
{
	pub(crate) inner: AssignedPoint<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS, P>,
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
						x_limbs[i] = Some(
							ctx.assign_advice(self.common.advice[i], Value::known(x.limbs[i]))
								.unwrap(),
						);
						y_limbs[i] = Some(
							ctx.assign_advice(
								self.common.advice[i + NUM_LIMBS],
								Value::known(y.limbs[i]),
							)
							.unwrap(),
						);
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
			.ok()
			.ok_or_else(|| AssertionFailure(annotation.to_string()))
	}

	fn multi_scalar_multiplication(
		pairs: &[(
			&<Self as ScalarLoader<C::Scalar>>::LoadedScalar,
			&Self::LoadedEcPoint,
		)],
	) -> Self::LoadedEcPoint {
		let config = pairs[0].1.loader.clone();
		let mut layouter = pairs[0].1.loader.layouter.lock().unwrap();
		let mut layouter_2 = pairs[1].1.loader.layouter.lock().unwrap();
		let auxes = pairs[0].1.loader.auxes.clone();
		let aux_init = auxes.0;
		let aux_fin = auxes.1;

		let point = pairs
			.iter()
			.cloned()
			.map(|(scalar, base)| {
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
				mul
			})
			.reduce(|acc, value| {
				let chip = EccAddChipset::new(acc.clone(), value.clone());
				let add = chip
					.synthesize(
						&config.common,
						&config.ecc_mul_scalar.add,
						layouter_2.namespace(|| "ecc_add"),
					)
					.unwrap();
				add
			})
			.unwrap();
		Halo2LEcPoint::new(point, config)
	}
}

impl<C: CurveAffine, L: Layouter<C::Scalar>, P> Loader<C> for LoaderConfig<C, L, P> where
	P: RnsParams<C::Base, C::Scalar, NUM_LIMBS, NUM_BITS>
{
}
