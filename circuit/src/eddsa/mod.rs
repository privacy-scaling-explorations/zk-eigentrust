/// Native implementation of EDDSA signature scheme
pub mod native;

use crate::{
	edwards::{params::EdwardsParams, AssignedPoint, EdwardsChip, EdwardsConfig},
	gadgets::{
		common::{CommonChip, CommonConfig},
		lt_eq::{LessEqualChip, LessEqualConfig},
	},
	params::RoundParams,
	poseidon::{PoseidonChip, PoseidonConfig},
};
use halo2wrong::{
	curves::FieldExt,
	halo2::{
		circuit::{AssignedCell, Layouter, Region},
		plonk::{Advice, Column, ConstraintSystem, Error},
	},
};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
/// Configuration elements for the circuit are defined here.
pub struct EddsaConfig {
	/// Constructs eddsa gadgets circuit elements.
	edwards: EdwardsConfig,
	/// Constructs common circuit elements.
	common: CommonConfig,
	/// Constructs lt_eq circuit elements.
	lt_eq: LessEqualConfig,
	/// Constructs poseidon circuit elements.
	poseidon: PoseidonConfig<5>,
	/// Configures a column for the temp.
	temp: Column<Advice>,
}

/// Constructs individual cells for the configuration elements.
pub struct EddsaChip<F: FieldExt, P: EdwardsParams<F>, R>
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

impl<F: FieldExt, P: EdwardsParams<F>, R> EddsaChip<F, P, R>
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

	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> EddsaConfig {
		let common = CommonChip::configure(meta);
		let edwards = EdwardsChip::<F, P>::configure(meta);
		let lt_eq = LessEqualChip::configure(meta);
		let poseidon = PoseidonChip::<_, 5, R>::configure(meta);
		let temp = meta.advice_column();

		meta.enable_equality(temp);

		EddsaConfig { edwards, common, lt_eq, poseidon, temp }
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self, config: &EddsaConfig, mut layouter: impl Layouter<F>,
	) -> Result<(), Error> {
		let (b8_x, b8_y, one, suborder) = layouter.assign_region(
			|| "assign_values",
			|mut region: Region<'_, F>| {
				let b8_x =
					region.assign_advice_from_constant(|| "b8_x", config.temp, 0, P::b8().0)?;
				let b8_y =
					region.assign_advice_from_constant(|| "b8_y", config.temp, 1, P::b8().1)?;
				let one = region.assign_advice_from_constant(|| "one", config.temp, 2, F::one())?;
				let suborder = region.assign_advice_from_constant(
					|| "suborder",
					config.temp,
					3,
					P::suborder(),
				)?;
				Ok((b8_x, b8_y, one, suborder))
			},
		)?;

		// s cannot be higher than the suborder.
		let lt_eq = LessEqualChip::new(
			self.s.clone(),
			suborder,
			self.s_bits,
			self.suborder_bits,
			self.s_suborder_diff_bits,
		);
		let is_lt_eq =
			lt_eq.synthesize(&config.lt_eq, layouter.namespace(|| "s_lt_eq_suborder"))?;

		// Cl = s * G
		let e = AssignedPoint::new(b8_x, b8_y, one.clone());
		let cl = EdwardsChip::<F, P>::scalar_mul::<252>(
			e,
			self.s.clone(),
			self.s_bits,
			&config.edwards,
			layouter.namespace(|| "b_8 * s"),
		)?;

		// H(R || PK || M)
		// Hashing R, public key and message composition.
		let m_hash_input = [
			self.big_r_x.clone(),
			self.big_r_y.clone(),
			self.pk_x.clone(),
			self.pk_y.clone(),
			self.m.clone(),
		];
		let hasher = PoseidonChip::<F, 5, R>::new(m_hash_input);
		let m_hash_res = hasher.synthesize(&config.poseidon, layouter.namespace(|| "m_hash"))?;

		// H(R || PK || M) * PK
		// Scalar multiplication for the public key and hash.
		let e = AssignedPoint::new(self.pk_x.clone(), self.pk_y.clone(), one.clone());
		let pk_h = EdwardsChip::<F, P>::scalar_mul::<256>(
			e,
			m_hash_res[0].clone(),
			self.m_hash_bits,
			&config.edwards,
			layouter.namespace(|| "pk * m_hash"),
		)?;

		// Cr = R + H(R || PK || M) * PK
		let big_r_point = AssignedPoint::new(self.big_r_x.clone(), self.big_r_y.clone(), one);
		let cr = EdwardsChip::<F, P>::add_point(
			big_r_point,
			pk_h,
			&config.edwards,
			layouter.namespace(|| "big_r + pk_h"),
		)?;

		// Converts two projective space points to their affine representation.
		let cl_affine = EdwardsChip::<F, P>::into_affine(
			cl,
			&config.edwards,
			layouter.namespace(|| "cl_affine"),
		)?;
		let cr_affine = EdwardsChip::<F, P>::into_affine(
			cr,
			&config.edwards,
			layouter.namespace(|| "cr_affine"),
		)?;

		// Check if Clx == Crx and Cly == Cry.
		let x_eq = CommonChip::is_equal(
			cl_affine.0,
			cr_affine.0,
			&config.common,
			layouter.namespace(|| "point_x_equal"),
		)?;
		let y_eq = CommonChip::is_equal(
			cl_affine.1,
			cr_affine.1,
			&config.common,
			layouter.namespace(|| "point_y_equal"),
		)?;

		// Use And gate between x and y equality.
		// If equal returns 1, else 0.
		let point_eq = CommonChip::and(
			x_eq,
			y_eq,
			&config.common,
			layouter.namespace(|| "point_eq"),
		)?;

		// Enforce equality.
		// If either one of them returns 0, the circuit will give an error.
		layouter.assign_region(
			|| "enforce_equal",
			|mut region: Region<'_, F>| {
				let lt_eq_copied =
					is_lt_eq.copy_advice(|| "lt_eq_temp", &mut region, config.temp, 0)?;
				let point_eq_copied =
					point_eq.copy_advice(|| "point_eq_temp", &mut region, config.temp, 1)?;
				region.constrain_constant(lt_eq_copied.cell(), F::one())?;
				region.constrain_constant(point_eq_copied.cell(), F::one())?;
				Ok(())
			},
		)?;

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::{EddsaChip, EddsaConfig};
	use crate::{
		eddsa::native::{sign, SecretKey},
		edwards::{
			native::Point,
			params::{BabyJubJub, EdwardsParams},
		},
		gadgets::{bits2num::to_bits, lt_eq::N_SHIFTED},
		params::poseidon_bn254_5x5::Params,
		poseidon::native::Poseidon,
		utils::{generate_params, prove_and_verify},
	};
	use halo2wrong::{
		curves::{
			bn256::{Bn256, Fr},
			group::ff::PrimeField,
		},
		halo2::{
			circuit::{Layouter, Region, SimpleFloorPlanner, Value},
			dev::MockProver,
			plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
		},
	};
	use rand::thread_rng;

	type Hasher = Poseidon<Fr, 5, Params>;

	#[derive(Clone)]
	struct TestConfig {
		eddsa: EddsaConfig,
		temp: Column<Advice>,
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
			let eddsa = EddsaChip::<Fr, BabyJubJub, Params>::configure(meta);
			let temp = meta.advice_column();

			meta.enable_equality(temp);

			TestConfig { eddsa, temp }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let (big_r_x, big_r_y, s, pk_x, pk_y, m) = layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, Fr>| {
					let big_r_x_assigned = region.assign_advice(
						|| "big_r_x",
						config.temp,
						0,
						|| Value::known(self.big_r_x),
					)?;
					let big_r_y_assigned = region.assign_advice(
						|| "big_r_y",
						config.temp,
						1,
						|| Value::known(self.big_r_y),
					)?;
					let s_assigned =
						region.assign_advice(|| "s", config.temp, 2, || Value::known(self.s))?;
					let pk_x_assigned = region.assign_advice(
						|| "pk_x",
						config.temp,
						3,
						|| Value::known(self.pk_x),
					)?;
					let pk_y_assigned = region.assign_advice(
						|| "pk_y",
						config.temp,
						4,
						|| Value::known(self.pk_y),
					)?;
					let m_assigned =
						region.assign_advice(|| "m", config.temp, 5, || Value::known(self.m))?;

					Ok((
						big_r_x_assigned, big_r_y_assigned, s_assigned, pk_x_assigned,
						pk_y_assigned, m_assigned,
					))
				},
			)?;

			let s_bits = to_bits(self.s.to_bytes()).map(Fr::from);
			let suborder = BabyJubJub::suborder();
			let suborder_bits = to_bits(suborder.to_bytes()).map(Fr::from);
			let diff = self.s + Fr::from_bytes(&N_SHIFTED).unwrap() - suborder;
			let diff_bits = to_bits(diff.to_bytes()).map(Fr::from);
			let h_inputs = [self.big_r_x, self.big_r_y, self.pk_x, self.pk_y, self.m];
			let res = Hasher::new(h_inputs).permute()[0];
			let m_hash_bits = to_bits(res.to_bytes()).map(Fr::from);
			let eddsa = EddsaChip::<Fr, BabyJubJub, Params>::new(
				big_r_x, big_r_y, s, pk_x, pk_y, m, s_bits, suborder_bits, diff_bits, m_hash_bits,
			);
			eddsa.synthesize(&config.eddsa, layouter.namespace(|| "eddsa"))?;
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
		let prover = MockProver::run(k, &circuit, vec![]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_eddsa_invalid_big_r() {
		// Testing invalid R.
		let mut rng = thread_rng();

		let sk = SecretKey::random(&mut rng);
		let pk = sk.public();

		let inputs = [Fr::zero(), Fr::one(), Fr::one(), Fr::zero(), Fr::zero()];
		let different_r = Hasher::new(inputs).permute()[0];

		let m = Fr::from_str_vartime("123456789012345678901234567890").unwrap();
		let mut sig = sign(&sk, &pk, m);
		let (b8_x, b8_y) = BabyJubJub::b8();
		let b8 = Point::new(b8_x, b8_y);
		sig.big_r = b8.mul_scalar(&different_r.to_bytes()).affine();
		let circuit = TestCircuit::new(sig.big_r.x, sig.big_r.y, sig.s, pk.0.x, pk.0.y, m);

		let k = 10;
		let prover = MockProver::run(k, &circuit, vec![]).unwrap();
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
		let prover = MockProver::run(k, &circuit, vec![]).unwrap();
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
		let prover = MockProver::run(k, &circuit, vec![]).unwrap();
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
		let prover = MockProver::run(k, &circuit, vec![]).unwrap();

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
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[], rng).unwrap();

		assert!(res);
	}
}
