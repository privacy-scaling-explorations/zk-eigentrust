/// Native implementation of EDDSA signature scheme
pub mod native;

use crate::{
	gadgets::{
		common::{CommonChip, CommonConfig, CommonEddsaConfig},
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
	common_eddsa: CommonEddsaConfig,
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
		let common = CommonChip::configure_gadgets(meta);
		let common_eddsa = CommonChip::<Fr>::configure_eddsa(meta);
		let lt_eq = LessEqualChip::configure(meta);
		let poseidon = PoseidonChip::<_, 5, Params>::configure(meta);
		let temp = meta.advice_column();

		meta.enable_equality(temp);

		EddsaConfig { common_eddsa, common, lt_eq, poseidon, temp }
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
		let cl = CommonChip::<Fr>::scalar_mul::<252>(
			b8_x,
			b8_y,
			one.clone(),
			self.s.clone(),
			self.s_bits,
			config.common_eddsa,
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
		let pk_h = CommonChip::<Fr>::scalar_mul::<256>(
			self.pk_x.clone(),
			self.pk_y.clone(),
			one.clone(),
			m_hash_res[0].clone(),
			self.m_hash_bits,
			config.common_eddsa,
			layouter.namespace(|| "pk * m_hash"),
		)?;

		// Cr = R + H(R || PK || M) * PK
		let cr = CommonChip::<Fr>::add_point(
			self.big_r_x.clone(),
			self.big_r_y.clone(),
			one,
			pk_h.0,
			pk_h.1,
			pk_h.2,
			config.common_eddsa,
			layouter.namespace(|| "big_r + pk_h"),
		)?;

		// Converts two projective space points to their affine representation.
		let cl_affine = CommonChip::<Fr>::into_affine(
			cl.0,
			cl.1,
			cl.2,
			config.common_eddsa.clone(),
			layouter.namespace(|| "cl_affine"),
		)?;
		let cr_affine = CommonChip::<Fr>::into_affine(
			cr.0,
			cr.1,
			cr.2,
			config.common_eddsa,
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
		eddsa::native::{
			ed_on_bn254::{B8, G},
			ops::add,
			sign, SecretKey,
		},
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
			plonk::{Circuit, Instance},
		},
	};
	use rand::thread_rng;
	type Hasher = Poseidon<Fr, 5, Params>;

	#[derive(Clone)]
	enum Gadgets {
		Eddsa,
		AddPoint,
		IntoAffine,
		ScalarMul,
	}

	#[derive(Clone)]
	struct TestConfig {
		eddsa: EddsaConfig,
		common_eddsa: CommonEddsaConfig,
		pub_ins: Column<Instance>,
		temp: Column<Advice>,
	}

	#[derive(Clone)]
	struct TestCircuit<const N: usize> {
		inputs: [Fr; N],
		gadget: Gadgets,
	}

	impl<const N: usize> TestCircuit<N> {
		fn new(inputs: [Fr; N], gadget: Gadgets) -> Self {
			Self { inputs, gadget }
		}
	}

	impl<const N: usize> Circuit<Fr> for TestCircuit<N> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			let eddsa = EddsaChip::configure(meta);
			let common_eddsa = CommonChip::<Fr>::configure_eddsa(meta);
			let pub_ins = meta.instance_column();
			let temp = meta.advice_column();

			meta.enable_equality(pub_ins);
			meta.enable_equality(temp);

			TestConfig { eddsa, common_eddsa, pub_ins, temp }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let mut items = Vec::new();
			for i in 0..N {
				items.push(layouter.assign_region(
					|| "temp",
					|mut region: Region<'_, Fr>| {
						let x = region.assign_advice(
							|| "temp_inputs",
							config.temp,
							i,
							|| Value::known(self.inputs[i]),
						)?;
						Ok(x)
					},
				)?);
			}
			match self.gadget {
				Gadgets::Eddsa => {
					let s_bits = to_bits(self.inputs[2].to_bytes()).map(Fr::from);
					let suborder_bits = to_bits(SUBORDER.to_bytes()).map(Fr::from);
					let diff = self.inputs[2] + Fr::from_bytes(&N_SHIFTED).unwrap() - SUBORDER;
					let diff_bits = to_bits(diff.to_bytes()).map(Fr::from);
					let h_inputs = [
						self.inputs[0], self.inputs[1], self.inputs[3], self.inputs[4],
						self.inputs[5],
					];
					let res = Poseidon::<_, 5, Params>::new(h_inputs).permute()[0];
					let m_hash_bits = to_bits(res.to_bytes()).map(Fr::from);
					let eddsa = EddsaChip::new(
						items[0].clone(),
						items[1].clone(),
						items[2].clone(),
						items[3].clone(),
						items[4].clone(),
						items[5].clone(),
						s_bits,
						suborder_bits,
						diff_bits,
						m_hash_bits,
					);
					eddsa.synthesize(config.eddsa, layouter.namespace(|| "eddsa"))?;
				},
				Gadgets::AddPoint => {
					let (x, y, z) = CommonChip::<Fr>::add_point(
						items[0].clone(),
						items[1].clone(),
						items[2].clone(),
						items[3].clone(),
						items[4].clone(),
						items[5].clone(),
						config.common_eddsa,
						layouter.namespace(|| "add"),
					)?;
					layouter.constrain_instance(x.cell(), config.pub_ins, 0)?;
					layouter.constrain_instance(y.cell(), config.pub_ins, 1)?;
					layouter.constrain_instance(z.cell(), config.pub_ins, 2)?;
				},
				Gadgets::IntoAffine => {
					let (x, y) = CommonChip::<Fr>::into_affine(
						items[0].clone(),
						items[1].clone(),
						items[2].clone(),
						config.common_eddsa,
						layouter.namespace(|| "into_affine"),
					)?;
					layouter.constrain_instance(x.cell(), config.pub_ins, 0)?;
					layouter.constrain_instance(y.cell(), config.pub_ins, 1)?;
				},
				Gadgets::ScalarMul => {
					let value_bits = to_bits::<256>(self.inputs[3].to_bytes()).map(Fr::from);
					let (x, y, z) = CommonChip::<Fr>::scalar_mul(
						items[0].clone(),
						items[1].clone(),
						items[2].clone(),
						items[3].clone(),
						value_bits,
						config.common_eddsa,
						layouter.namespace(|| "scalar_mul"),
					)?;
					layouter.constrain_instance(x.cell(), config.pub_ins, 0)?;
					layouter.constrain_instance(y.cell(), config.pub_ins, 1)?;
					layouter.constrain_instance(z.cell(), config.pub_ins, 2)?;
				},
			}
			Ok(())
		}
	}

	// TEST CASES FOR THE EDDSA CIRCUIT
	// In Eddsa test cases sending a dummy instance doesn't
	// affect the circuit output because it is not constrained.
	#[test]
	fn test_eddsa() {
		// Testing a valid case.
		let mut rng = thread_rng();

		let sk = SecretKey::random(&mut rng);
		let pk = sk.public();

		let m = Fr::from_str_vartime("123456789012345678901234567890").unwrap();
		let sig = sign(&sk, &pk, m);
		let circuit = TestCircuit::new(
			[sig.big_r.x, sig.big_r.y, sig.s, pk.0.x, pk.0.y, m],
			Gadgets::Eddsa,
		);

		let k = 10;
		let dummy_instance = vec![Fr::zero()];
		let prover = MockProver::run(k, &circuit, vec![dummy_instance]).unwrap();
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
		let circuit = TestCircuit::new(
			[sig.big_r.x, sig.big_r.y, sig.s, pk.0.x, pk.0.y, m],
			Gadgets::Eddsa,
		);

		let k = 10;
		let dummy_instance = vec![Fr::zero()];
		let prover = MockProver::run(k, &circuit, vec![dummy_instance]).unwrap();
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
		let circuit = TestCircuit::new(
			[sig.big_r.x, sig.big_r.y, sig.s, pk.0.x, pk.0.y, m],
			Gadgets::Eddsa,
		);

		let k = 10;
		let dummy_instance = vec![Fr::zero()];
		let prover = MockProver::run(k, &circuit, vec![dummy_instance]).unwrap();
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
		let circuit = TestCircuit::new(
			[sig.big_r.x, sig.big_r.y, sig.s, pk2.0.x, pk2.0.y, m],
			Gadgets::Eddsa,
		);
		let k = 10;
		let dummy_instance = vec![Fr::zero()];
		let prover = MockProver::run(k, &circuit, vec![dummy_instance]).unwrap();
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
		let circuit = TestCircuit::new(
			[sig.big_r.x, sig.big_r.y, sig.s, pk.0.x, pk.0.y, m2],
			Gadgets::Eddsa,
		);

		let k = 10;
		let dummy_instance = vec![Fr::zero()];
		let prover = MockProver::run(k, &circuit, vec![dummy_instance]).unwrap();

		assert!(prover.verify().is_err());
	}

	#[test]
	fn test_eddsa_production() {
		let mut rng = thread_rng();

		let sk = SecretKey::random(&mut rng);
		let pk = sk.public();

		let m = Fr::from_str_vartime("123456789012345678901234567890").unwrap();
		let sig = sign(&sk, &pk, m);
		let circuit = TestCircuit::new(
			[sig.big_r.x, sig.big_r.y, sig.s, pk.0.x, pk.0.y, m],
			Gadgets::Eddsa,
		);

		let k = 10;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let dummy_instance = vec![Fr::zero()];
		let res =
			prove_and_verify::<Bn256, _, _>(params, circuit, &[&dummy_instance], rng).unwrap();

		assert!(res);
	}

	// TEST CASES FOR THE ADD_POINT CIRCUIT
	#[test]
	fn should_add_point() {
		// Testing a valid case.
		let r = B8.projective();
		let e = G.projective();
		let (x_res, y_res, z_res) = add(r.x, r.y, r.z, e.x, e.y, e.z);
		let circuit = TestCircuit::new([r.x, r.y, r.z, e.x, e.y, e.z], Gadgets::AddPoint);

		let k = 7;
		let pub_ins = vec![x_res, y_res, z_res];
		let prover = MockProver::run(k, &circuit, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_add_point_production() {
		let r = B8.projective();
		let e = G.projective();
		let (x_res, y_res, z_res) = add(r.x, r.y, r.z, e.x, e.y, e.z);
		let circuit = TestCircuit::new([r.x, r.y, r.z, e.x, e.y, e.z], Gadgets::AddPoint);

		let k = 9;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let pub_ins = [x_res, y_res, z_res];
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[&pub_ins], rng).unwrap();

		assert!(res);
	}

	// TEST CASES FOR THE INTO_AFFINE CIRCUIT
	#[test]
	fn should_into_affine_point() {
		// Testing a valid case.
		let r = B8.projective();
		let r_affine = r.affine();
		let circuit = TestCircuit::new([r.x, r.y, r.z], Gadgets::IntoAffine);

		let k = 7;
		let pub_ins = vec![r_affine.x, r_affine.y];
		let prover = MockProver::run(k, &circuit, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_into_affine_point_production() {
		let r = B8.projective();
		let r_affine = r.affine();
		let circuit = TestCircuit::new([r.x, r.y, r.z], Gadgets::IntoAffine);

		let k = 9;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let pub_ins = vec![r_affine.x, r_affine.y];
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[&pub_ins], rng).unwrap();

		assert!(res);
	}

	//TEST CASES FOR THE SCALAR_MUL CIRCUIT
	#[test]
	fn should_mul_point_with_scalar() {
		// Testing scalar as value 8.
		let scalar = Fr::from(8);
		let r = B8.projective();
		let res = B8.mul_scalar(&scalar.to_bytes());
		let circuit = TestCircuit::new([r.x, r.y, r.z, scalar], Gadgets::ScalarMul);

		let k = 9;
		let pub_ins = vec![res.x, res.y, res.z];
		let prover = MockProver::run(k, &circuit, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_scalar_mul_zero() {
		// Testing scalar as value 0.
		let scalar = Fr::from(0);
		let r = B8.projective();
		let res = B8.mul_scalar(&scalar.to_bytes());
		let circuit = TestCircuit::new([r.x, r.y, r.z, scalar], Gadgets::ScalarMul);

		let k = 9;
		let pub_ins = vec![res.x, res.y, res.z];
		let prover = MockProver::run(k, &circuit, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_scalar_mul_one() {
		// Testing scalar as value 1.
		let scalar = Fr::from(1);
		let r = B8.projective();
		let res = B8.mul_scalar(&scalar.to_bytes());
		let circuit = TestCircuit::new([r.x, r.y, r.z, scalar], Gadgets::ScalarMul);

		let k = 9;
		let pub_ins = vec![res.x, res.y, res.z];
		let prover = MockProver::run(k, &circuit, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn should_mul_point_with_scalar_production() {
		let scalar = Fr::from(8);
		let r = B8.projective();
		let res = B8.mul_scalar(&scalar.to_bytes());
		let circuit = TestCircuit::new([r.x, r.y, r.z, scalar], Gadgets::ScalarMul);

		let k = 9;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let pub_ins = [res.x, res.y, res.z];
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[&pub_ins], rng).unwrap();

		assert!(res);
	}
}
