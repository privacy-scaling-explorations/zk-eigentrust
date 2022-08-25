use std::vec;

use crate::utils::to_wide;
use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};

use super::{
	bits2num::{Bits2NumChip, Bits2NumConfig},
	is_zero::{IsZeroChip, IsZeroConfig},
};

const N_SHIFTED: [u8; 32] = [
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
];

#[derive(Clone)]
pub struct LessEqualConfig {
	bits2num: Bits2NumConfig,
	is_zero: IsZeroConfig,
	x: Column<Advice>,
	y: Column<Advice>,
	selector: Selector,
}

pub struct LessEqualChip<F: FieldExt> {
	x: AssignedCell<F, F>,
	y: AssignedCell<F, F>,
	n2b_input_bits: [F; 252],
}

impl<F: FieldExt> LessEqualChip<F> {
	pub fn new(x: AssignedCell<F, F>, y: AssignedCell<F, F>, n2b_input_bits: [F; 252]) -> Self {
		LessEqualChip {
			x,
			y,
			n2b_input_bits,
		}
	}

	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> LessEqualConfig {
		let bits2num = Bits2NumChip::<_, 252>::configure(meta);
		let is_zero = IsZeroChip::configure(meta);
		let x = meta.advice_column();
		let y = meta.advice_column();
		let s = meta.selector();

		meta.enable_equality(x);
		meta.enable_equality(y);

		let n_shifted = F::from_bytes_wide(&to_wide(&N_SHIFTED));

		meta.create_gate("x + n_shifted - y", |v_cells| {
			let n_shifted_exp = Expression::Constant(n_shifted);

			let s_exp = v_cells.query_selector(s);
			let x_exp = v_cells.query_advice(x, Rotation::cur());
			let y_exp = v_cells.query_advice(y, Rotation::cur());

			let x_next_exp = v_cells.query_advice(x, Rotation::next());

			vec![s_exp * ((x_exp + n_shifted_exp - y_exp) - x_next_exp)]
		});

		LessEqualConfig {
			bits2num,
			is_zero,
			x,
			y,
			selector: s,
		}
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self,
		config: LessEqualConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		let inp = layouter.assign_region(
			|| "less_than_equal",
			|mut region: Region<'_, F>| {
				config.selector.enable(&mut region, 0)?;
				let assigned_x = self.x.copy_advice(|| "x", &mut region, config.x, 0)?;
				let assigned_y = self.y.copy_advice(|| "y", &mut region, config.y, 0)?;

				let n_shifted = Value::known(F::from_bytes_wide(&to_wide(&N_SHIFTED)));
				let res = assigned_x.value().cloned() + n_shifted - assigned_y.value();

				let assigned_res =
					region.assign_advice(|| "x + n_shift - y", config.x, 1, || res)?;
				Ok(assigned_res)
			},
		)?;

		let bits2num = Bits2NumChip::new(inp, self.n2b_input_bits);
		let bits = bits2num.synthesize(config.bits2num, layouter.namespace(|| "bits2num"))?;

		let is_zero = IsZeroChip::new(bits[251].clone());
		let res = is_zero.synthesize(config.is_zero, layouter.namespace(|| "is_zero"))?;
		Ok(res)
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
		lt_eq: LessEqualConfig,
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
			let lt_eq = LessEqualChip::<Fr>::configure(meta);
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
			let (x, y) = layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, Fr>| {
					let x = region.assign_advice(
						|| "temp_x",
						config.temp,
						0,
						|| Value::known(self.x),
					)?;
					let y = region.assign_advice(
						|| "temp_y",
						config.temp,
						1,
						|| Value::known(self.y),
					)?;

					Ok((x, y))
				},
			)?;
			let n_shifted = Fr::from_bytes(&N_SHIFTED).unwrap();
			let b = self.x + n_shifted - self.y;
			let b2n_bits = to_bits(b.to_bytes()).map(Fr::from);
			let lt_eq_chip = LessEqualChip::<Fr>::new(x, y, b2n_bits);
			let res = lt_eq_chip.synthesize(config.lt_eq, layouter.namespace(|| "less_eq"))?;

			layouter.constrain_instance(res.cell(), config.pub_ins, 0)?;
			Ok(())
		}
	}

	#[test]
	fn test_less_than() {
		let x = Fr::from(8);
		let y = Fr::from(4);
		// let n_shifted = Fr::from_bytes(&N_SHIFTED).unwrap();
		// let b = x + n_shifted - y;
		// let b_bits = to_bits::<NUM_BITS>(b.to_bytes()).map(|v| if v { "1" } else {
		// "0" }).join(""); println!("{:?}", b_bits);
		// println!("{:?}", b_bits.len());

		// let n_shifted: u8 = 0b10000000;

		// let a1: u8 = 0b00000010;
		// let b1: u8 = 0b00000100;

		// let a2: u8 = 0b00000100;
		// let b2: u8 = 0b00000010;

		// let a3: u8 = 0b00010000;
		// let b3: u8 = 0b00100000;

		// let a4: u8 = 0b00100000;
		// let b4: u8 = 0b00010000;

		// println!("{:08b}", a1 + n_shifted - b1);
		// println!("{:08b}", a2 + n_shifted - b2);
		// println!("{:08b}", a3 + n_shifted - b3);
		// println!("{:08b}", a4 + n_shifted - b4);

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
