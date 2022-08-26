pub mod add;
pub mod into_affine;
pub mod native;
pub mod scalar_mul;

use self::{
	add::{PointAddChip, PointAddConfig},
	into_affine::{IntoAffineChip, IntoAffineConfig},
	scalar_mul::{ScalarMulChip, ScalarMulConfig},
};
use crate::{
	gadgets::{
		and::{AndChip, AndConfig},
		is_equal::{IsEqualChip, IsEqualConfig},
		lt_eq::{LessEqualChip, LessEqualConfig},
	},
	poseidon::{params::bn254_5x5::Params5x5Bn254, PoseidonChip, PoseidonConfig},
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
struct EddsaConfig {
	scalar_mul_s: ScalarMulConfig,
	scalar_mul_mh: ScalarMulConfig,
	lt_eq: LessEqualConfig,
	point_add: PointAddConfig,
	into_affine: IntoAffineConfig,
	poseidon: PoseidonConfig<5>,
	is_eq: IsEqualConfig,
	and: AndConfig,
	temp: Column<Advice>,
}

struct EddsaChip {
	big_r_x: AssignedCell<Fr, Fr>,
	big_r_y: AssignedCell<Fr, Fr>,
	s: AssignedCell<Fr, Fr>,
	pk_x: AssignedCell<Fr, Fr>,
	pk_y: AssignedCell<Fr, Fr>,
	m: AssignedCell<Fr, Fr>,
	s_bits: [Fr; 252],
	suborder_bits: [Fr; 252],
	s_suborder_diff_bits: [Fr; 253],
	m_hash_bits: [Fr; 256],
}

impl EddsaChip {
	fn new(
		big_r_x: AssignedCell<Fr, Fr>,
		big_r_y: AssignedCell<Fr, Fr>,
		s: AssignedCell<Fr, Fr>,
		pk_x: AssignedCell<Fr, Fr>,
		pk_y: AssignedCell<Fr, Fr>,
		m: AssignedCell<Fr, Fr>,
		s_bits: [Fr; 252],
		suborder_bits: [Fr; 252],
		s_suborder_diff_bits: [Fr; 253],
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
}

impl EddsaChip {
	pub fn configure(meta: &mut ConstraintSystem<Fr>) -> EddsaConfig {
		let scalar_mul_s = ScalarMulChip::<252>::configure(meta);
		let scalar_mul_mh = ScalarMulChip::<256>::configure(meta);
		let lt_eq = LessEqualChip::configure(meta);
		let point_add = PointAddChip::configure(meta);
		let into_affine = IntoAffineChip::configure(meta);
		let poseidon = PoseidonChip::<_, 5, Params5x5Bn254>::configure(meta);
		let is_eq = IsEqualChip::configure(meta);
		let and = AndChip::configure(meta);
		let temp = meta.advice_column();

		meta.enable_equality(temp);

		EddsaConfig {
			scalar_mul_s,
			scalar_mul_mh,
			lt_eq,
			point_add,
			into_affine,
			poseidon,
			is_eq,
			and,
			temp,
		}
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self,
		config: EddsaConfig,
		mut layouter: impl Layouter<Fr>,
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

		let lt_eq = LessEqualChip::new(
			self.s.clone(),
			suborder,
			self.s_bits,
			self.suborder_bits,
			self.s_suborder_diff_bits,
		);
		let is_lt_eq = lt_eq.synthesize(config.lt_eq, layouter.namespace(|| "s_lt_eq_suborder"))?;

		let scalar_mul1 = ScalarMulChip::new(b8_x, b8_y, one.clone(), self.s.clone(), self.s_bits);
		let cl = scalar_mul1.synthesize(config.scalar_mul_s, layouter.namespace(|| "b_8 * s"))?;

		let m_hash_input = [
			self.big_r_x.clone(),
			self.big_r_y.clone(),
			self.pk_x.clone(),
			self.pk_y.clone(),
			self.m.clone(),
		];
		let hasher = PoseidonChip::<_, 5, Params5x5Bn254>::new(m_hash_input);
		let m_hash_res = hasher.synthesize(config.poseidon, layouter.namespace(|| "m_hash"))?;

		let scalar_mul2 = ScalarMulChip::new(
			self.pk_x.clone(),
			self.pk_y.clone(),
			one.clone(),
			m_hash_res[0].clone(),
			self.m_hash_bits,
		);
		let pk_h =
			scalar_mul2.synthesize(config.scalar_mul_mh, layouter.namespace(|| "pk * m_hash"))?;

		let point_add = PointAddChip::new(
			self.big_r_x.clone(),
			self.big_r_y.clone(),
			one,
			pk_h.0,
			pk_h.1,
			pk_h.2,
		);
		let cr = point_add.synthesize(config.point_add, layouter.namespace(|| "big_r + pk_h"))?;

		let into_affine1 = IntoAffineChip::new(cl.0, cl.1, cl.2);
		let into_affine2 = IntoAffineChip::new(cr.0, cr.1, cr.2);

		let cl_affine = into_affine1.synthesize(
			config.into_affine.clone(),
			layouter.namespace(|| "cl_affine"),
		)?;
		let cr_affine =
			into_affine2.synthesize(config.into_affine, layouter.namespace(|| "cr_affine"))?;

		let is_eq1 = IsEqualChip::new(cl_affine.0, cr_affine.0);
		let is_eq2 = IsEqualChip::new(cl_affine.1, cr_affine.1);

		let x_eq =
			is_eq1.synthesize(config.is_eq.clone(), layouter.namespace(|| "point_x_equal"))?;
		let y_eq = is_eq2.synthesize(config.is_eq, layouter.namespace(|| "point_y_equal"))?;

		let and = AndChip::new(x_eq, y_eq);
		let point_eq = and.synthesize(config.and, layouter.namespace(|| "point_eq"))?;

		layouter.assign_region(
			|| "enforce_equal",
			|mut region: Region<'_, Fr>| {
				region.constrain_constant(is_lt_eq.cell(), Fr::one())?;
				region.constrain_constant(point_eq.cell(), Fr::one())?;
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
			plonk::{Circuit, Instance},
		},
	};
	use rand::thread_rng;

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
			Self {
				big_r_x,
				big_r_y,
				s,
				pk_x,
				pk_y,
				m,
			}
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
			&self,
			config: TestConfig,
			mut layouter: impl Layouter<Fr>,
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
						big_r_x_assigned,
						big_r_y_assigned,
						s_assigned,
						pk_x_assigned,
						pk_y_assigned,
						m_assigned,
					))
				},
			)?;

			let s_bits = to_bits(self.s.to_bytes()).map(Fr::from);
			let suborder_bits = to_bits(SUBORDER.to_bytes()).map(Fr::from);
			let diff = self.s + Fr::from_bytes(&N_SHIFTED).unwrap() - SUBORDER;
			let diff_bits = to_bits(diff.to_bytes()).map(Fr::from);
			let h_inputs = [self.big_r_x, self.big_r_y, self.pk_x, self.pk_y, self.m];
			let res = Poseidon::<_, 5, Params5x5Bn254>::new(h_inputs).permute()[0];
			let m_hash_bits = to_bits(res.to_bytes()).map(Fr::from);
			let eddsa = EddsaChip::new(
				big_r_x,
				big_r_y,
				s,
				pk_x,
				pk_y,
				m,
				s_bits,
				suborder_bits,
				diff_bits,
				m_hash_bits,
			);
			eddsa.synthesize(config.eddsa, layouter.namespace(|| "eddsa"))?;
			Ok(())
		}
	}

	#[test]
	fn test_eddsa() {
		let mut rng = thread_rng();

		let sk = SecretKey::random(&mut rng);
		let pk = sk.public();

		let m = Fr::from_str_vartime("123456789012345678901234567890").unwrap();
		let sig = sign(&sk, &pk, m);
		let circuit = TestCircuit::new(sig.big_r.x, sig.big_r.y, sig.s, pk.0.x, pk.0.y, m);

		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_eddsa_production() {
		let mut rng = thread_rng();

		let sk = SecretKey::random(&mut rng);
		let pk = sk.public();

		let m = Fr::from_str_vartime("123456789012345678901234567890").unwrap();
		let sig = sign(&sk, &pk, m);
		let circuit = TestCircuit::new(sig.big_r.x, sig.big_r.y, sig.s, pk.0.x, pk.0.y, m);

		let k = 9;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[], rng).unwrap();

		assert!(res);
	}
}
