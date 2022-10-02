/// Implementation for the EDDSA circuit gadgets.
pub mod eddsa_gadgets;
/// Native implementation of EDDSA signature scheme
pub mod native;

use crate::{
	eddsa::eddsa_gadgets::{EddsaGadgetsChip, EddsaGadgetsConfig},
	gadgets::{
		common::{CommonChip, CommonConfig},
		lt_eq::{LessEqualChip, LessEqualConfig},
	},
	params::poseidon_bn254_5x5::Params,
	poseidon::{PoseidonChip, PoseidonConfig},
};
use halo2wrong::{
	curves::bn256::Fr,
	halo2::{
		circuit::{AssignedCell, Layouter, Region, Value},
		plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
		poly::Rotation,
	},
};
use native::ed_on_bn254::{B8, SUBORDER};

#[derive(Clone)]
/// Configuration elements for the circuit are defined here.
struct EddsaConfig {
	/// Constructs common eddsa circuit elements.
	eddsa_gadgets: EddsaGadgetsConfig,
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
struct EddsaChip {
	/// Assigns a cell for the big_r_x.
	big_r_x: AssignedCell<Fr, Fr>,
	/// Assigns a cell for the big_r_y.
	big_r_y: AssignedCell<Fr, Fr>,
	/// Assigns a cell for the s.
	s: AssignedCell<Fr, Fr>,
	/// Assigns a cell for the pk_x.
	pk_x: AssignedCell<Fr, Fr>,
	/// Assigns a cell for the pk_y.
	pk_y: AssignedCell<Fr, Fr>,
	/// Assigns a cell for the m.
	m: AssignedCell<Fr, Fr>,
	/// Constructs an array for the s_bits.
	s_bits: [Fr; 252],
	/// Constructs an array for the suborder_bits.
	suborder_bits: [Fr; 252],
	/// Constructs an array for the s_suborder_diff_bits.
	s_suborder_diff_bits: [Fr; 253],
	/// Constructs an array for the m_hash_bits.
	m_hash_bits: [Fr; 256],
}

impl EddsaChip {
	/// Create a new chip.
	fn new(
		big_r_x: AssignedCell<Fr, Fr>, big_r_y: AssignedCell<Fr, Fr>, s: AssignedCell<Fr, Fr>,
		pk_x: AssignedCell<Fr, Fr>, pk_y: AssignedCell<Fr, Fr>, m: AssignedCell<Fr, Fr>,
		s_bits: [Fr; 252], suborder_bits: [Fr; 252], s_suborder_diff_bits: [Fr; 253],
		m_hash_bits: [Fr; 256],
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
		}
	}

	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<Fr>) -> EddsaConfig {
		let common = CommonChip::configure(meta);
		let eddsa_gadgets = EddsaGadgetsChip::configure(meta);
		let lt_eq = LessEqualChip::configure(meta);
		let poseidon = PoseidonChip::<_, 5, Params>::configure(meta);
		let temp = meta.advice_column();

		meta.enable_equality(temp);

		EddsaConfig { eddsa_gadgets, common, lt_eq, poseidon, temp }
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self, config: EddsaConfig, mut layouter: impl Layouter<Fr>,
	) -> Result<(), Error> {
		let (b8_x, b8_y, one, suborder) = layouter.assign_region(
			|| "assign_values",
			|mut region: Region<'_, Fr>| {
				let b8_x = region.assign_advice_from_constant(|| "b8_x", config.temp, 0, B8.x)?;
				let b8_y = region.assign_advice_from_constant(|| "b8_y", config.temp, 1, B8.y)?;
				let one =
					region.assign_advice_from_constant(|| "one", config.temp, 2, Fr::one())?;
				let suborder =
					region.assign_advice_from_constant(|| "suborder", config.temp, 3, SUBORDER)?;
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
		let is_lt_eq = lt_eq.synthesize(config.lt_eq, layouter.namespace(|| "s_lt_eq_suborder"))?;

		// Cl = s * G
		let cl = EddsaGadgetsChip::scalar_mul::<252>(
			b8_x,
			b8_y,
			one.clone(),
			self.s.clone(),
			self.s_bits,
			config.eddsa_gadgets.clone(),
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
		let hasher = PoseidonChip::<_, 5, Params>::new(m_hash_input);
		let m_hash_res = hasher.synthesize(config.poseidon, layouter.namespace(|| "m_hash"))?;

		// H(R || PK || M) * PK
		// Scalar multiplication for the public key and hash.
		let pk_h = EddsaGadgetsChip::scalar_mul::<256>(
			self.pk_x.clone(),
			self.pk_y.clone(),
			one.clone(),
			m_hash_res[0].clone(),
			self.m_hash_bits,
			config.eddsa_gadgets.clone(),
			layouter.namespace(|| "pk * m_hash"),
		)?;

		// Cr = R + H(R || PK || M) * PK
		let cr = EddsaGadgetsChip::add_point(
			self.big_r_x.clone(),
			self.big_r_y.clone(),
			one,
			pk_h.0,
			pk_h.1,
			pk_h.2,
			config.eddsa_gadgets.clone(),
			layouter.namespace(|| "big_r + pk_h"),
		)?;

		// Converts two projective space points to their affine representation.
		let cl_affine = EddsaGadgetsChip::into_affine(
			cl.0,
			cl.1,
			cl.2,
			config.eddsa_gadgets.clone(),
			layouter.namespace(|| "cl_affine"),
		)?;
		let cr_affine = EddsaGadgetsChip::into_affine(
			cr.0,
			cr.1,
			cr.2,
			config.eddsa_gadgets,
			layouter.namespace(|| "cr_affine"),
		)?;

		// Check if Clx == Crx and Cly == Cry.
		let x_eq = CommonChip::is_equal(
			cl_affine.0,
			cr_affine.0,
			config.common.clone(),
			layouter.namespace(|| "point_x_equal"),
		)?;
		let y_eq = CommonChip::is_equal(
			cl_affine.1,
			cr_affine.1,
			config.common,
			layouter.namespace(|| "point_y_equal"),
		)?;

		// Use And gate between x and y equality.
		// If equal returns 1, else 0.
		let point_eq =
			CommonChip::and(x_eq, y_eq, config.common, layouter.namespace(|| "point_eq"))?;

		// Enforce equality.
		// If either one of them returns 0, the circuit will give an error.
		layouter.assign_region(
			|| "enforce_equal",
			|mut region: Region<'_, Fr>| {
				let lt_eq_copied =
					is_lt_eq.copy_advice(|| "lt_eq_temp", &mut region, config.temp, 0)?;
				let point_eq_copied =
					point_eq.copy_advice(|| "point_eq_temp", &mut region, config.temp, 1)?;
				region.constrain_constant(lt_eq_copied.cell(), Fr::one())?;
				region.constrain_constant(point_eq_copied.cell(), Fr::one())?;
				Ok(())
			},
		)?;

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		eddsa::native::{ed_on_bn254::B8, sign, SecretKey},
		gadgets::{bits2num::to_bits, lt_eq::N_SHIFTED},
		poseidon::native::Poseidon,
		utils::{generate_params, prove_and_verify},
	};
	use halo2wrong::{
		curves::{
			bn256::{Bn256, Fr},
			group::ff::PrimeField,
		},
		halo2::{
			circuit::{SimpleFloorPlanner, Value},
			dev::MockProver,
			plonk::Circuit,
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
			let eddsa = EddsaChip::configure(meta);
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
			let suborder_bits = to_bits(SUBORDER.to_bytes()).map(Fr::from);
			let diff = self.s + Fr::from_bytes(&N_SHIFTED).unwrap() - SUBORDER;
			let diff_bits = to_bits(diff.to_bytes()).map(Fr::from);
			let h_inputs = [self.big_r_x, self.big_r_y, self.pk_x, self.pk_y, self.m];
			let res = Poseidon::<_, 5, Params>::new(h_inputs).permute()[0];
			let m_hash_bits = to_bits(res.to_bytes()).map(Fr::from);
			let eddsa = EddsaChip::new(
				big_r_x, big_r_y, s, pk_x, pk_y, m, s_bits, suborder_bits, diff_bits, m_hash_bits,
			);
			eddsa.synthesize(config.eddsa, layouter.namespace(|| "eddsa"))?;
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
		sig.big_r = B8.mul_scalar(&different_r.to_bytes()).affine();
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
