use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};

/// Converts given bytes to the bits.
pub fn to_bits<const B: usize, const N: usize>(num: [u8; N]) -> [bool; B] {
	let mut bits = [false; B];
	if N == 0 {
		bits
	} else {
		for i in 0..B {
			bits[i] = num[i / 8] & (1 << (i % 8)) != 0;
		}
		bits
	}
}

/// Configuration elements for the circuit defined here.
#[derive(Clone)]
pub struct Bits2NumConfig {
	/// Configures a column for the bits.
	pub bits: Column<Advice>,
	/// Configures a column for the lc1.
	lc1: Column<Advice>,
	/// Configures a column for the e2.
	e2: Column<Advice>,
	/// Configures a fixed boolean value for each row of the circuit.
	selector: Selector,
}

/// Constructs a cell and a variable for the circuit.
#[derive(Clone)]
pub struct Bits2NumChip<F: FieldExt, const B: usize> {
	/// Assigns a cell for the value.
	value: AssignedCell<F, F>,
	/// Constructs bits variable for the circuit.
	bits: [Value<F>; B],
}

impl<F: FieldExt, const B: usize> Bits2NumChip<F, B> {
	/// Create a new chip.
	pub fn new(value: AssignedCell<F, F>, bits: [F; B]) -> Self {
		Self { value, bits: bits.map(|b| Value::known(b)) }
	}

	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> Bits2NumConfig {
		let bits = meta.advice_column();
		let lc1 = meta.advice_column();
		let e2 = meta.advice_column();
		let fixed = meta.fixed_column();
		let s = meta.selector();

		meta.enable_equality(bits);
		meta.enable_equality(lc1);
		meta.enable_equality(e2);
		meta.enable_constant(fixed);

		meta.create_gate("bits2num", |v_cells| {
			let one_exp = Expression::Constant(F::one());
			let bit_exp = v_cells.query_advice(bits, Rotation::cur());

			let e2_exp = v_cells.query_advice(e2, Rotation::cur());
			let e2_next_exp = v_cells.query_advice(e2, Rotation::next());

			let lc1_exp = v_cells.query_advice(lc1, Rotation::cur());
			let lc1_next_exp = v_cells.query_advice(lc1, Rotation::next());

			let s_exp = v_cells.query_selector(s);

			vec![
				// bit * (1 - bit) == 0
				// Constraining bit to be a boolean.
				s_exp.clone() * (bit_exp.clone() * (one_exp - bit_exp.clone())),
				// e2 + e2 == e2_next
				// Starting from 1, doubling.
				s_exp.clone() * ((e2_exp.clone() + e2_exp.clone()) - e2_next_exp),
				// lc1 + bit * e2 == lc1_next
				// If the bit is equal to 1, e2 will be added to the sum.
				// Example:
				// bit = 1
				// e2 = 1 (first rotation)
				// lc1 = 0
				// If the bit == 1, double the e2.
				// This will be used in the next rotation, if bit == 1 again. (e2_next = 1 + 1 = 2)
				//
				// Check the constraint => (1 * 1 + 0)
				// lc1_next = 1
				s_exp * ((bit_exp * e2_exp + lc1_exp) - lc1_next_exp),
			]
		});

		Bits2NumConfig { bits, lc1, e2, selector: s }
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self, config: Bits2NumConfig, mut layouter: impl Layouter<F>,
	) -> Result<[AssignedCell<F, F>; B], Error> {
		layouter.assign_region(
			|| "bits2num",
			|mut region: Region<'_, F>| {
				let mut lc1 =
					region.assign_advice_from_constant(|| "lc1_0", config.lc1, 0, F::zero())?;
				let mut e2 =
					region.assign_advice_from_constant(|| "e2_0", config.e2, 0, F::one())?;

				let mut bits: [Option<AssignedCell<F, F>>; B] = [(); B].map(|_| None);
				for i in 0..self.bits.len() {
					config.selector.enable(&mut region, i)?;

					let bit = region.assign_advice(|| "bits", config.bits, i, || self.bits[i])?;
					bits[i] = Some(bit.clone());

					let next_lc1 =
						lc1.value().cloned() + bit.value().cloned() * e2.value().cloned();
					let next_e2 = e2.value().cloned() + e2.value();

					lc1 = region.assign_advice(|| "lc1", config.lc1, i + 1, || next_lc1)?;
					e2 = region.assign_advice(|| "e2", config.e2, i + 1, || next_e2)?;
				}

				region.constrain_equal(self.value.cell(), lc1.cell())?;

				Ok(bits.map(|b| b.unwrap()))
			},
		)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::utils::{generate_params, prove_and_verify};
	use halo2wrong::{
		curves::bn256::{Bn256, Fr},
		halo2::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit},
	};

	#[derive(Clone)]
	struct TestConfig {
		bits2num: Bits2NumConfig,
		temp: Column<Advice>,
	}

	#[derive(Clone)]
	struct TestCircuit<const N: usize> {
		numba: Fr,
		bytes: [u8; N],
	}

	impl<const N: usize> TestCircuit<N> {
		fn new(x: Fr, y: [u8; N]) -> Self {
			Self { numba: x, bytes: y }
		}
	}

	impl<const N: usize> Circuit<Fr> for TestCircuit<N> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			let bits2num = Bits2NumChip::<_, 256>::configure(meta);
			let temp = meta.advice_column();

			meta.enable_equality(temp);

			TestConfig { bits2num, temp }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let numba = layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, Fr>| {
					region.assign_advice(|| "temp_x", config.temp, 0, || Value::known(self.numba))
				},
			)?;

			let bits = to_bits::<256, N>(self.bytes).map(|b| Fr::from(b));
			let bits2num = Bits2NumChip::new(numba, bits);
			let _ = bits2num.synthesize(config.bits2num, layouter.namespace(|| "bits2num"))?;
			Ok(())
		}
	}

	#[test]
	fn test_bits_to_num() {
		// Testing field element 0x01234567890abcdef.
		let numba = Fr::from(1311768467294899695u64);
		let numba_bytes = [
			239, 205, 171, 144, 120, 86, 52, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0,
		];

		let circuit = TestCircuit::new(numba, numba_bytes);
		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_bits_to_num_big() {
		// Testing biggest value in the field.
		let numba = Fr::zero().sub(&Fr::one());
		let numba_bytes = [
			0, 0, 0, 240, 147, 245, 225, 67, 145, 112, 185, 121, 72, 232, 51, 40, 93, 88, 129, 129,
			182, 69, 80, 184, 41, 160, 49, 225, 114, 78, 100, 48,
		];

		let circuit = TestCircuit::new(numba, numba_bytes);
		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_bits_to_num_big_plus() {
		// Testing biggest value + 1.
		let numba_bytes = [
			1, 0, 0, 240, 147, 245, 225, 67, 145, 112, 185, 121, 72, 232, 51, 40, 93, 88, 129, 129,
			182, 69, 80, 184, 41, 160, 49, 225, 114, 78, 100, 48,
		];

		let circuit = TestCircuit::new(Fr::zero(), numba_bytes);
		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_bits_to_num_zero_value() {
		// Testing zero as value.
		let circuit = TestCircuit::new(Fr::zero(), []);
		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_bits_to_num_production() {
		let numba = Fr::from(1311768467294899695u64);
		let numba_bytes = [
			239, 205, 171, 144, 120, 86, 52, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0,
		];

		let circuit = TestCircuit::new(numba, numba_bytes);
		let k = 9;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[], rng).unwrap();

		assert!(res);
	}
}
