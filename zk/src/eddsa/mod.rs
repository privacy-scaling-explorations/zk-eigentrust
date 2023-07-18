/// Native implementation of EDDSA signature scheme
pub mod native;

use crate::{
	edwards::{
		params::{BabyJubJub, EdwardsParams},
		AssignedPoint, IntoAffineChip, PointAddChip, StrictScalarMulChipset, StrictScalarMulConfig,
	},
	gadgets::lt_eq::{LessEqualChipset, LessEqualConfig},
	params::hasher::{poseidon_bn254_5x5::Params, RoundParams},
	poseidon::{PoseidonChipset, PoseidonConfig},
	Chip, Chipset, CommonConfig, FieldExt, RegionCtx,
};
use halo2::{
	circuit::{AssignedCell, Layouter, Region},
	halo2curves::bn256::Fr as Scalar,
	plonk::{Error, Selector},
};
use std::marker::PhantomData;

/// Type alias for Eddsa chip on BabyJubJub elliptic curve
pub type Eddsa = EddsaChipset<Scalar, BabyJubJub, Params>;

#[derive(Clone, Debug)]
/// Selector configuration for Eddsa
pub struct EddsaConfig {
	poseidon: PoseidonConfig,
	lt_eq: LessEqualConfig,
	scalar_mul: StrictScalarMulConfig,
	add_point_selector: Selector,
	affine_selector: Selector,
}

impl EddsaConfig {
	/// Construct Eddsa config from selectors
	pub fn new(
		poseidon: PoseidonConfig, lt_eq: LessEqualConfig, scalar_mul: StrictScalarMulConfig,
		add_point_selector: Selector, affine_selector: Selector,
	) -> Self {
		Self { poseidon, lt_eq, scalar_mul, add_point_selector, affine_selector }
	}
}

/// Constructs individual cells for the configuration elements.
pub struct EddsaChipset<F: FieldExt, P: EdwardsParams<F>, R>
where
	R: RoundParams<F, 5>,
{
	/// Assigns a cell for the big_r_x.
	big_r_x: AssignedCell<F, F>,
	/// Assigns a cell for the big_r_y.
	big_r_y: AssignedCell<F, F>,
	/// Assigns a cell for the s.
	s: AssignedCell<F, F>,
	/// Assigns a cell for the pk_x.
	pk_x: AssignedCell<F, F>,
	/// Assigns a cell for the pk_y.
	pk_y: AssignedCell<F, F>,
	/// Assigns a cell for the m.
	m: AssignedCell<F, F>,
	_p: PhantomData<P>,
	_r: PhantomData<R>,
}

impl<F: FieldExt, P: EdwardsParams<F>, R> EddsaChipset<F, P, R>
where
	R: RoundParams<F, 5>,
{
	/// Create a new chip.
	pub fn new(
		big_r_x: AssignedCell<F, F>, big_r_y: AssignedCell<F, F>, s: AssignedCell<F, F>,
		pk_x: AssignedCell<F, F>, pk_y: AssignedCell<F, F>, m: AssignedCell<F, F>,
	) -> Self {
		Self { big_r_x, big_r_y, s, pk_x, pk_y, m, _p: PhantomData, _r: PhantomData }
	}
}

impl<F: FieldExt, P: EdwardsParams<F>, R> Chipset<F> for EddsaChipset<F, P, R>
where
	R: RoundParams<F, 5>,
{
	type Config = EddsaConfig;
	type Output = ();

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		let (b8_x, b8_y, one, suborder) = layouter.assign_region(
			|| "assign_values",
			|region: Region<'_, F>| {
				let mut ctx = RegionCtx::new(region, 0);
				let b8_x = ctx.assign_from_constant(common.advice[0], P::b8().0)?;
				let b8_y = ctx.assign_from_constant(common.advice[1], P::b8().1)?;
				let one = ctx.assign_from_constant(common.advice[2], F::ONE)?;
				let suborder = ctx.assign_from_constant(common.advice[3], P::suborder())?;
				Ok((b8_x, b8_y, one, suborder))
			},
		)?;

		// s cannot be higher than the suborder.
		let lt_eq_chipset = LessEqualChipset::new(self.s.clone(), suborder);
		let is_lt_eq = lt_eq_chipset.synthesize(
			common,
			&config.lt_eq,
			layouter.namespace(|| "s_lt_eq_suborder"),
		)?;

		// Cl = s * G
		let e = AssignedPoint::new(b8_x, b8_y, one.clone());
		let cl_chipset = StrictScalarMulChipset::<F, P>::new(e, self.s.clone());
		let cl =
			cl_chipset.synthesize(common, &config.scalar_mul, layouter.namespace(|| "b_8 * s"))?;

		// H(R || PK || M)
		// Hashing R, public key and message composition.
		let m_hash_input = [
			self.big_r_x.clone(),
			self.big_r_y.clone(),
			self.pk_x.clone(),
			self.pk_y.clone(),
			self.m.clone(),
		];
		let hasher = PoseidonChipset::<F, 5, R>::new(m_hash_input);
		let m_hash_res =
			hasher.synthesize(common, &config.poseidon, layouter.namespace(|| "m_hash"))?;

		// H(R || PK || M) * PK
		// Scalar multiplication for the public key and hash.
		let e = AssignedPoint::new(self.pk_x.clone(), self.pk_y.clone(), one.clone());
		let pk_h_chipset = StrictScalarMulChipset::<F, P>::new(e, m_hash_res[0].clone());
		let pk_h = pk_h_chipset.synthesize(
			common,
			&config.scalar_mul,
			layouter.namespace(|| "pk * m_hash"),
		)?;

		// Cr = R + H(R || PK || M) * PK
		let big_r_point = AssignedPoint::new(self.big_r_x.clone(), self.big_r_y, one);
		let cr_chip = PointAddChip::<F, P>::new(big_r_point, pk_h);
		let cr = cr_chip.synthesize(
			common,
			&config.add_point_selector,
			layouter.namespace(|| "big_r + pk_h"),
		)?;

		// Converts two projective space points to their affine representation.
		let cl_affine_chip = IntoAffineChip::new(cl);
		let cl_affine = cl_affine_chip.synthesize(
			common,
			&config.affine_selector,
			layouter.namespace(|| "cl_affine"),
		)?;
		let cr_affine_chip = IntoAffineChip::new(cr);
		let cr_affine = cr_affine_chip.synthesize(
			common,
			&config.affine_selector,
			layouter.namespace(|| "cr_affine"),
		)?;

		// Enforce equality.
		// Check if Clx == Crx and Cly == Cry.
		layouter.assign_region(
			|| "enforce_equal",
			|region: Region<'_, F>| {
				let mut region_ctx = RegionCtx::new(region, 0);

				let cl_affine_x = region_ctx.copy_assign(common.advice[0], cl_affine.0.clone())?;
				let cl_affine_y = region_ctx.copy_assign(common.advice[1], cl_affine.1.clone())?;
				let cr_affine_x = region_ctx.copy_assign(common.advice[2], cr_affine.0.clone())?;
				let cr_affine_y = region_ctx.copy_assign(common.advice[3], cr_affine.1.clone())?;
				let lt_eq = region_ctx.copy_assign(common.advice[4], is_lt_eq.clone())?;

				region_ctx.constrain_equal(cl_affine_x, cr_affine_x)?;
				region_ctx.constrain_equal(cl_affine_y, cr_affine_y)?;
				region_ctx.constrain_to_constant(lt_eq, F::ONE)?;
				Ok(())
			},
		)?;

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::{EddsaChipset, EddsaConfig};
	use crate::{
		eddsa::native::{sign, SecretKey},
		edwards::{
			native::Point,
			params::{BabyJubJub, EdwardsParams},
			IntoAffineChip, PointAddChip, ScalarMulChip, StrictScalarMulConfig,
		},
		gadgets::{
			bits2num::Bits2NumChip,
			lt_eq::{LessEqualConfig, NShiftedChip},
			main::{MainChip, MainConfig},
		},
		params::hasher::poseidon_bn254_5x5::Params,
		poseidon::{native::Poseidon, FullRoundChip, PartialRoundChip, PoseidonConfig},
		utils::{generate_params, prove_and_verify},
		Chip, Chipset, CommonConfig, RegionCtx,
	};
	use halo2::{
		circuit::{Layouter, Region, SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::{
			bn256::{Bn256, Fr},
			group::ff::PrimeField,
		},
		plonk::{Circuit, ConstraintSystem, Error},
	};
	use rand::thread_rng;

	type PoseidonHasher = Poseidon<Fr, 5, Params>;
	type FrChip = FullRoundChip<Fr, 5, Params>;
	type PrChip = PartialRoundChip<Fr, 5, Params>;

	#[derive(Clone)]
	struct TestConfig {
		common: CommonConfig,
		eddsa: EddsaConfig,
	}

	#[derive(Clone)]
	struct TestCircuit {
		big_r_x: Value<Fr>,
		big_r_y: Value<Fr>,
		s: Value<Fr>,
		pk_x: Value<Fr>,
		pk_y: Value<Fr>,
		m: Value<Fr>,
	}

	impl TestCircuit {
		fn new(big_r_x: Fr, big_r_y: Fr, s: Fr, pk_x: Fr, pk_y: Fr, m: Fr) -> Self {
			Self {
				big_r_x: Value::known(big_r_x),
				big_r_y: Value::known(big_r_y),
				s: Value::known(s),
				pk_x: Value::known(pk_x),
				pk_y: Value::known(pk_y),
				m: Value::known(m),
			}
		}
	}

	impl Circuit<Fr> for TestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self {
				big_r_x: Value::unknown(),
				big_r_y: Value::unknown(),
				s: Value::unknown(),
				pk_x: Value::unknown(),
				pk_y: Value::unknown(),
				m: Value::unknown(),
			}
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			let common = CommonConfig::new(meta);
			let main = MainConfig::new(MainChip::configure(&common, meta));

			let full_round_selector = FrChip::configure(&common, meta);
			let partial_round_selector = PrChip::configure(&common, meta);
			let poseidon = PoseidonConfig::new(full_round_selector, partial_round_selector);

			let bits2num_selector = Bits2NumChip::configure(&common, meta);
			let n_shifted_selector = NShiftedChip::configure(&common, meta);
			let lt_eq = LessEqualConfig::new(main, bits2num_selector, n_shifted_selector);

			let scalar_mul_selector = ScalarMulChip::<_, BabyJubJub>::configure(&common, meta);
			let strict_scalar_mul =
				StrictScalarMulConfig::new(bits2num_selector, scalar_mul_selector);

			let add_point_selector = PointAddChip::<_, BabyJubJub>::configure(&common, meta);
			let affine_selector = IntoAffineChip::configure(&common, meta);

			let eddsa = EddsaConfig::new(
				poseidon, lt_eq, strict_scalar_mul, add_point_selector, affine_selector,
			);

			TestConfig { common, eddsa }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let (big_r_x, big_r_y, s, pk_x, pk_y, m) = layouter.assign_region(
				|| "temp",
				|region: Region<'_, Fr>| {
					let mut ctx = RegionCtx::new(region, 0);

					let big_r_x = ctx.assign_advice(config.common.advice[0], self.big_r_x)?;
					let big_r_y = ctx.assign_advice(config.common.advice[1], self.big_r_y)?;
					let s = ctx.assign_advice(config.common.advice[2], self.s)?;
					let pk_x = ctx.assign_advice(config.common.advice[3], self.pk_x)?;
					let pk_y = ctx.assign_advice(config.common.advice[4], self.pk_y)?;
					let m = ctx.assign_advice(config.common.advice[5], self.m)?;

					Ok((big_r_x, big_r_y, s, pk_x, pk_y, m))
				},
			)?;

			let eddsa =
				EddsaChipset::<Fr, BabyJubJub, Params>::new(big_r_x, big_r_y, s, pk_x, pk_y, m);
			eddsa.synthesize(
				&config.common,
				&config.eddsa,
				layouter.namespace(|| "eddsa"),
			)?;
			Ok(())
		}
	}

	#[test]
	fn test_eddsa() {
		// Testing a valid case.
		let mut rng = thread_rng();

		let sk = SecretKey::random(&mut rng);
		let pk = sk.public();

		let m = Fr::from_str_vartime("123456789012345678901234567890").unwrap();
		let sig = sign(&sk, &pk, m);
		let circuit = TestCircuit::new(sig.big_r.x, sig.big_r.y, sig.s, pk.0.x, pk.0.y, m);

		let k = 10;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_eddsa_invalid_big_r() {
		// Testing invalid R.
		let mut rng = thread_rng();

		let sk = SecretKey::random(&mut rng);
		let pk = sk.public();

		let inputs = [Fr::zero(), Fr::one(), Fr::one(), Fr::zero(), Fr::zero()];
		let different_r = PoseidonHasher::new(inputs).permute()[0];

		let m = Fr::from_str_vartime("123456789012345678901234567890").unwrap();
		let mut sig = sign(&sk, &pk, m);
		let (b8_x, b8_y) = BabyJubJub::b8();
		let b8 = Point::new(b8_x, b8_y);
		sig.big_r = b8.mul_scalar(different_r).affine();
		let circuit = TestCircuit::new(sig.big_r.x, sig.big_r.y, sig.s, pk.0.x, pk.0.y, m);

		let k = 10;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
		assert!(prover.verify().is_err());
	}

	#[test]
	fn test_eddsa_invalid_s() {
		// Testing invalid s.
		let mut rng = thread_rng();

		let sk = SecretKey::random(&mut rng);
		let pk = sk.public();

		let m = Fr::from_str_vartime("123456789012345678901234567890").unwrap();
		let mut sig = sign(&sk, &pk, m);
		sig.s = sig.s.add(&Fr::from(1));
		let circuit = TestCircuit::new(sig.big_r.x, sig.big_r.y, sig.s, pk.0.x, pk.0.y, m);

		let k = 10;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
		assert!(prover.verify().is_err());
	}

	#[test]
	fn test_eddsa_invalid_pk() {
		// Testing invalid public key.
		let mut rng = thread_rng();

		let sk1 = SecretKey::random(&mut rng);
		let pk1 = sk1.public();

		let sk2 = SecretKey::random(&mut rng);
		let pk2 = sk2.public();

		let m = Fr::from_str_vartime("123456789012345678901234567890").unwrap();
		let sig = sign(&sk1, &pk1, m);
		let circuit = TestCircuit::new(sig.big_r.x, sig.big_r.y, sig.s, pk2.0.x, pk2.0.y, m);
		let k = 10;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
		assert!(prover.verify().is_err());
	}

	#[test]
	fn test_eddsa_invalid_message() {
		// Testing invalid message.
		let mut rng = thread_rng();

		let sk = SecretKey::random(&mut rng);
		let pk = sk.public();

		let m1 = Fr::from_str_vartime("123456789012345678901234567890").unwrap();
		let m2 = Fr::from_str_vartime("123456789012345678901234567890123123").unwrap();

		let sig = sign(&sk, &pk, m1);
		let circuit = TestCircuit::new(sig.big_r.x, sig.big_r.y, sig.s, pk.0.x, pk.0.y, m2);

		let k = 10;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();

		assert!(prover.verify().is_err());
	}

	#[test]
	fn test_eddsa_production() {
		let mut rng = thread_rng();

		let sk = SecretKey::random(&mut rng);
		let pk = sk.public();

		let m = Fr::from_str_vartime("123456789012345678901234567890").unwrap();
		let sig = sign(&sk, &pk, m);
		let circuit = TestCircuit::new(sig.big_r.x, sig.big_r.y, sig.s, pk.0.x, pk.0.y, m);

		let k = 10;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[&[]], rng).unwrap();

		assert!(res);
	}
}
