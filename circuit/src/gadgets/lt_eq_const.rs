use std::vec;

use super::bits2num::{Bits2NumChip, Bits2NumConfig};
use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
	poly::Rotation,
};

#[derive(Clone)]
pub struct LessEqualConstConfig {
	bits2num: Bits2NumConfig,
	const_bits: [Column<Fixed>; 4],
	var_bits: [Column<Advice>; 2],
	acc: Column<Advice>,
	a: Column<Advice>,
	selector: Selector,
	selector2: Selector,
}

pub struct LessEqualConstChip<F: FieldExt> {
	x: AssignedCell<F, F>,
	constant: [[F; 4]; 127],
	acc_bits: [F; 127],
	// Max bits a passed number should have
	x_bits: [F; 254],
}

impl<F: FieldExt> LessEqualConstChip<F> {
	pub fn new(
		x: AssignedCell<F, F>,
		constant: [[F; 4]; 127],
		acc_bits: [F; 127],
		x_bits: [F; 254],
	) -> Self {
		LessEqualConstChip {
			x,
			constant,
			acc_bits,
			x_bits,
		}
	}

	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> LessEqualConstConfig {
		let bits2num = Bits2NumChip::<_, 254>::configure(meta);
		let const_bits = [(); 4].map(|_| meta.fixed_column());
		let var_bits = [(); 2].map(|_| meta.advice_column());
		let acc = meta.advice_column();
		let a = meta.advice_column();
		let s = meta.selector();

		let s2 = meta.selector();

		meta.create_gate("accumulate_bits", |v_cells| {
			let one = Expression::Constant(F::one());
			let two = Expression::Constant(F::from(2));

			let const_bits_exp = const_bits.map(|v| v_cells.query_fixed(v, Rotation::cur()));

			let acc_exp = v_cells.query_advice(acc, Rotation::cur());
			let acc_next_exp = v_cells.query_advice(acc, Rotation::next());
			let a_exp = v_cells.query_advice(a, Rotation::cur());
			let a_next_exp = v_cells.query_advice(a, Rotation::next());

			let sig_u = v_cells.query_advice(var_bits[0], Rotation::cur());
			let sig_l = v_cells.query_advice(var_bits[1], Rotation::cur());

			let const_bits_sum = const_bits_exp[0].clone()
				+ const_bits_exp[1].clone()
				+ const_bits_exp[2].clone()
				+ const_bits_exp[3].clone();

			let case_0 = const_bits_exp[0].clone()
				* (sig_l.clone() + sig_u.clone() - sig_l.clone() * sig_u.clone());

			let case_1 = const_bits_exp[1].clone()
				* (sig_l.clone() + two.clone() * sig_u.clone()
					- sig_l.clone() * sig_u.clone()
					- one.clone());

			let case_2 = const_bits_exp[2].clone()
				* (sig_l.clone() * sig_u.clone() + sig_u.clone() - one.clone());

			let case_3 = const_bits_exp[3].clone() * (sig_l.clone() * sig_u.clone() - one.clone());

			let case_sum = case_0 + case_1 + case_2 + case_3;

			let next_acc = acc_exp + case_sum * a_exp.clone();
			let next_a = a_exp * two;

			let s_exp = v_cells.query_selector(s);

			vec![
				// NOTE: TAKEN FROM circomlib/compconstant.circom
				// (1 - x) * x == 0
				// Check that each const bit is actially a bit
				s_exp.clone()
					* (one.clone() - const_bits_exp[0].clone())
					* const_bits_exp[0].clone(),
				s_exp.clone()
					* (one.clone() - const_bits_exp[1].clone())
					* const_bits_exp[1].clone(),
				s_exp.clone()
					* (one.clone() - const_bits_exp[2].clone())
					* const_bits_exp[2].clone(),
				s_exp.clone()
					* (one.clone() - const_bits_exp[3].clone())
					* const_bits_exp[3].clone(),
				// (1 - x) * x == 0
				// Check that each variable bit is actially a bit
				s_exp.clone() * (one.clone() - sig_u.clone()) * sig_u,
				s_exp.clone() * (one.clone() - sig_l.clone()) * sig_l,
				// Check that sum of all const bits is one,
				// which means that only one bit can be positive
				s_exp.clone() * (const_bits_sum - one),
				// check `acc` and `a`
				s_exp.clone() * (acc_next_exp - next_acc),
				s_exp * (a_next_exp - next_a),
			]
		});

		meta.create_gate("acc = acc + a - 1", |v_cells| {
			let one = Expression::Constant(F::one());

			let acc_exp = v_cells.query_advice(acc, Rotation::cur());
			let acc_next_exp = v_cells.query_advice(acc, Rotation::next());
			let a_exp = v_cells.query_advice(a, Rotation::cur());

			let s2_exp = v_cells.query_selector(s2);
			let new_acc = acc_exp + a_exp - one;

			vec![s2_exp * (acc_next_exp - new_acc)]
		});

		LessEqualConstConfig {
			bits2num,
			const_bits,
			var_bits,
			acc,
			a,
			selector: s,
			selector2: s2,
		}
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self,
		config: LessEqualConstConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		let bits2num_x = Bits2NumChip::new(self.x.clone(), self.x_bits);
		let bits =
			bits2num_x.synthesize(config.bits2num.clone(), layouter.namespace(|| "x_bits2num"))?;

		let (acc, a) = layouter.assign_region(
			|| "less_than_equal_const",
			|mut region: Region<'_, F>| {
				config.selector.enable(&mut region, 0)?;

				for i in 0..self.constant.len() {
					let const_bits = self.constant[i];

					region.assign_fixed(
						|| "const_bit",
						config.const_bits[0],
						i,
						|| Value::known(const_bits[0]),
					)?;
					region.assign_fixed(
						|| "const_bit",
						config.const_bits[1],
						i,
						|| Value::known(const_bits[1]),
					)?;
					region.assign_fixed(
						|| "const_bit",
						config.const_bits[2],
						i,
						|| Value::known(const_bits[2]),
					)?;
					region.assign_fixed(
						|| "const_bit",
						config.const_bits[3],
						i,
						|| Value::known(const_bits[3]),
					)?;

					bits[i * 2].copy_advice(|| "sig_u", &mut region, config.var_bits[0], i)?;
					bits[i * 2 + 1].copy_advice(|| "sig_l", &mut region, config.var_bits[1], i)?;
				}

				let mut acc = F::zero();
				let mut a = F::one();

				let mut accs: [Option<F>; 127] = [(); 127].map(|_| None);
				let mut ais: [Option<F>; 127] = [(); 127].map(|_| None);
				accs[0] = Some(acc);
				ais[0] = Some(a);

				for i in 0..self.constant.len() {
					let one = F::one();
					let two = F::from(2);
					let consts = self.constant[i];

					let sig_u = self.x_bits[i * 2];
					let sig_l = self.x_bits[i * 2 + 1];

					let part = if consts[0] == F::one() {
						sig_l + sig_u - sig_l * sig_u
					} else if consts[1] == F::one() {
						sig_l + two * sig_u - sig_l * sig_u - one
					} else if consts[2] == F::one() {
						sig_l * sig_u + sig_u - one
					} else {
						sig_l * sig_u - one
					};

					acc = acc + part * a;
					a = a * two;

					accs[i + 1] = Some(acc);
					ais[i + 1] = Some(a);
				}

				region.assign_advice_from_constant(|| "acc_0", config.acc, 0, accs[0].unwrap())?;
				region.assign_advice_from_constant(|| "a_0", config.a, 0, ais[0].unwrap())?;

				let mut final_acc: Option<AssignedCell<F, F>> = None;
				let mut final_a: Option<AssignedCell<F, F>> = None;
				for i in 1..=self.constant.len() {
					final_acc = Some(region.assign_advice(
						|| "acc",
						config.acc,
						i,
						|| Value::known(accs[i].unwrap()),
					)?);
					final_a = Some(region.assign_advice(
						|| "a",
						config.a,
						i,
						|| Value::known(ais[i].unwrap()),
					)?);
				}

				Ok((final_acc.unwrap(), final_a.unwrap()))
			},
		)?;

		let acc_final = layouter.assign_region(
			|| "acc = acc + a - 1",
			|mut region: Region<'_, F>| {
				config.selector2.enable(&mut region, 0)?;

				let one = Value::known(F::one());
				let acc = acc.copy_advice(|| "new_acc", &mut region, config.acc, 0)?;
				let a = a.copy_advice(|| "new_a", &mut region, config.a, 0)?;

				let acc_final = acc.value().cloned() + a.value() - one;

				let acc_final_cell =
					region.assign_advice(|| "acc_final", config.acc, 1, || acc_final)?;
				Ok(acc_final_cell)
			},
		)?;

		let bits2num_acc = Bits2NumChip::new(acc_final, self.acc_bits);
		let bits = bits2num_acc.synthesize(config.bits2num, layouter.namespace(|| "x_bits2num"))?;

		Ok(bits[127].clone())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		gadgets::bits2num::to_bits,
		utils::{generate_params, prove_and_verify},
	};
	use halo2wrong::{
		curves::bn256::{Bn256, Fr},
		halo2::{
			circuit::{SimpleFloorPlanner, Value},
			dev::MockProver,
			plonk::{Circuit, Instance},
		},
	};

	#[derive(Clone)]
	struct TestConfig {
		lt_eq: LessEqualConstConfig,
		temp: Column<Advice>,
		pub_ins: Column<Instance>,
	}

	#[derive(Clone)]
	struct TestCircuit {
		x: Fr,
		y: Fr,
	}

	impl TestCircuit {
		fn new(x: Fr, y: Fr) -> Self {
			Self { x, y }
		}
	}

	impl Circuit<Fr> for TestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			let lt_eq = LessEqualConstChip::configure(meta);
			let temp = meta.advice_column();
			let pub_ins = meta.instance_column();

			meta.enable_equality(temp);
			meta.enable_equality(pub_ins);

			TestConfig {
				lt_eq,
				temp,
				pub_ins,
			}
		}

		fn synthesize(
			&self,
			config: TestConfig,
			mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			Ok(())
		}
	}

	#[test]
	fn test_less_than() {
		let x = Fr::from(8);
		let y = Fr::from(4);

		let test_chip = TestCircuit::new(x, y);

		let k = 9;
		let pub_ins = vec![Fr::from(0)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	#[ignore = "skip"]
	fn test_less_than_production() {
		let x = Fr::from(8);
		let y = Fr::from(4);
		let test_chip = TestCircuit::new(x, y);

		let k = 9;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let pub_ins = [Fr::from(0)];
		let res = prove_and_verify::<Bn256, _, _>(params, test_chip, &[&pub_ins], rng).unwrap();

		assert!(res);
	}
}
