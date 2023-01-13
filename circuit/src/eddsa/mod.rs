/// Native implementation of EDDSA signature scheme
pub mod native;

use crate::{
	edwards::{
		params::EdwardsParams, AssignedPoint, IntoAffineChip, PointAddChip, StrictScalarMulChipset,
		StrictScalarMulConfig,
	},
	gadgets::lt_eq::{LessEqualChipset, LessEqualConfig},
	params::RoundParams,
	poseidon::{PoseidonChipset, PoseidonConfig},
	Chip, Chipset, CommonConfig, RegionCtx,
};
use halo2::{
	circuit::{AssignedCell, Layouter, Region},
	halo2curves::FieldExt,
	plonk::{Error, Selector},
};
use std::marker::PhantomData;

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
	/// Constructs an array for the s_bits.
	s_bits: [F; 252],
	/// Constructs an array for the suborder_bits.
	suborder_bits: [F; 252],
	/// Constructs an array for the s_suborder_diff_bits.
	s_suborder_diff_bits: [F; 253],
	/// Constructs an array for the m_hash_bits.
	m_hash_bits: [F; 256],
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
		s_bits: [F; 252], suborder_bits: [F; 252], s_suborder_diff_bits: [F; 253],
		m_hash_bits: [F; 256],
	) -> Self {
		Self {
			big_r_x,
			big_r_y,
			s,
			pk_x,
			pk_y,
			m,
			s_bits,
			suborder_bits,
			s_suborder_diff_bits,
			m_hash_bits,
			_p: PhantomData,
			_r: PhantomData,
		}
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
				let one = ctx.assign_from_constant(common.advice[2], F::one())?;
				let suborder = ctx.assign_from_constant(common.advice[3], P::suborder())?;
				Ok((b8_x, b8_y, one, suborder))
			},
		)?;

		// s cannot be higher than the suborder.
		let lt_eq_chipset = LessEqualChipset::new(
			self.s.clone(),
			suborder,
			self.s_bits,
			self.suborder_bits,
			self.s_suborder_diff_bits,
		);
		let is_lt_eq = lt_eq_chipset.synthesize(
			common,
			&config.lt_eq,
			layouter.namespace(|| "s_lt_eq_suborder"),
		)?;

		// Cl = s * G
		let e = AssignedPoint::new(b8_x, b8_y, one.clone());
		let cl_chipset =
			StrictScalarMulChipset::<F, P>::new(e, self.s.clone(), self.s_bits.to_vec());
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
		let pk_h_chipset = StrictScalarMulChipset::<F, P>::new(
			e,
			m_hash_res[0].clone(),
			self.m_hash_bits.to_vec(),
		);
		let pk_h = pk_h_chipset.synthesize(
			common,
			&config.scalar_mul,
			layouter.namespace(|| "pk * m_hash"),
		)?;

		// Cr = R + H(R || PK || M) * PK
		let big_r_point = AssignedPoint::new(self.big_r_x.clone(), self.big_r_y.clone(), one);
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
				region_ctx.constrain_to_constant(lt_eq, F::one())?;
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
			bits2num::{to_bits, Bits2NumChip},
			common::IsZeroChip,
			lt_eq::{LessEqualConfig, NShiftedChip, N_SHIFTED},
		},
		params::poseidon_bn254_5x5::Params,
		poseidon::{native::Poseidon, FullRoundChip, PartialRoundChip, PoseidonConfig},
		utils::{generate_params, prove_and_verify},
		Chip, Chipset, CommonChip, CommonConfig, RegionCtx,
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
		big_r_x: Fr,
		big_r_y: Fr,
		s: Fr,
		pk_x: Fr,
		pk_y: Fr,
		m: Fr,
	}

	impl TestCircuit {
		fn new(big_r_x: Fr, big_r_y: Fr, s: Fr, pk_x: Fr, pk_y: Fr, m: Fr) -> Self {
			Self { big_r_x, big_r_y, s, pk_x, pk_y, m }
		}
	}

	impl Circuit<Fr> for TestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			let common = CommonChip::configure(meta);

			let full_round_selector = FrChip::configure(&common, meta);
			let partial_round_selector = PrChip::configure(&common, meta);
			let poseidon = PoseidonConfig::new(full_round_selector, partial_round_selector);

			let bits2num_selector = Bits2NumChip::configure(&common, meta);
			let n_shifted_selector = NShiftedChip::configure(&common, meta);
			let is_zero_selector = IsZeroChip::configure(&common, meta);
			let lt_eq =
				LessEqualConfig::new(bits2num_selector, n_shifted_selector, is_zero_selector);

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

					let big_r_x_val = Value::known(self.big_r_x);
					let big_r_y_val = Value::known(self.big_r_y);
					let s_val = Value::known(self.s);
					let pk_x_val = Value::known(self.pk_x);
					let pk_y_val = Value::known(self.pk_y);
					let m_val = Value::known(self.m);

					let big_r_x = ctx.assign_advice(config.common.advice[0], big_r_x_val)?;
					let big_r_y = ctx.assign_advice(config.common.advice[1], big_r_y_val)?;
					let s = ctx.assign_advice(config.common.advice[2], s_val)?;
					let pk_x = ctx.assign_advice(config.common.advice[3], pk_x_val)?;
					let pk_y = ctx.assign_advice(config.common.advice[4], pk_y_val)?;
					let m = ctx.assign_advice(config.common.advice[5], m_val)?;

					Ok((big_r_x, big_r_y, s, pk_x, pk_y, m))
				},
			)?;

			let s_bits = to_bits(self.s.to_bytes()).map(Fr::from);
			let suborder = BabyJubJub::suborder();
			let suborder_bits = to_bits(suborder.to_bytes()).map(Fr::from);
			let diff = self.s + Fr::from_bytes(&N_SHIFTED).unwrap() - suborder;
			let diff_bits = to_bits(diff.to_bytes()).map(Fr::from);
			let h_inputs = [self.big_r_x, self.big_r_y, self.pk_x, self.pk_y, self.m];
			let res = PoseidonHasher::new(h_inputs).permute()[0];
			let m_hash_bits = to_bits(res.to_bytes()).map(Fr::from);
			let eddsa = EddsaChipset::<Fr, BabyJubJub, Params>::new(
				big_r_x, big_r_y, s, pk_x, pk_y, m, s_bits, suborder_bits, diff_bits, m_hash_bits,
			);
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

		let k = 11;
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
		sig.big_r = b8.mul_scalar(&different_r.to_bytes()).affine();
		let circuit = TestCircuit::new(sig.big_r.x, sig.big_r.y, sig.s, pk.0.x, pk.0.y, m);

		let k = 11;
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

		let k = 11;
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
		let k = 11;
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

		let k = 11;
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

		let k = 11;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[&[]], rng).unwrap();

		assert!(res);
	}
}
