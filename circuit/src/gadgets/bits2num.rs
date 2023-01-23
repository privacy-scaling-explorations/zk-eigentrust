use crate::{Chip, RegionCtx};
use halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};

use crate::CommonConfig;

/// Converts given bytes to the bits.
pub fn to_bits<const B: usize>(num: [u8; 32]) -> [bool; B] {
	let mut bits = [false; B];
	for i in 0..B {
		bits[i] = num[i / 8] & (1 << (i % 8)) != 0;
	}
	bits
}

/// Constructs a cell and a variable for the circuit.
#[derive(Clone)]
pub struct Bits2NumChip<F: FieldExt> {
	/// Assigns a cell for the value.
	value: AssignedCell<F, F>,
	/// Constructs bits variable for the circuit.
	bits: Vec<Value<F>>,
}

impl<F: FieldExt> Bits2NumChip<F> {
	/// Create a new chip.
	pub fn new(value: AssignedCell<F, F>, bits: Vec<F>) -> Self {
		let bit_vals = bits.into_iter().map(Value::known).collect();
		Self { value, bits: bit_vals }
	}
}

impl<F: FieldExt> Chip<F> for Bits2NumChip<F> {
	type Output = Vec<AssignedCell<F, F>>;

	/// Make the circuit config.
	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector {
		let selector = meta.selector();

		meta.create_gate("bits2num", |v_cells| {
			let one_exp = Expression::Constant(F::one());
			let bit_exp = v_cells.query_advice(common.advice[0], Rotation::cur());

			let e2_exp = v_cells.query_advice(common.advice[1], Rotation::cur());
			let e2_next_exp = v_cells.query_advice(common.advice[1], Rotation::next());

			let lc1_exp = v_cells.query_advice(common.advice[2], Rotation::cur());
			let lc1_next_exp = v_cells.query_advice(common.advice[2], Rotation::next());

			let s_exp = v_cells.query_selector(selector);

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

		selector
	}

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, selector: &Selector, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		layouter.assign_region(
			|| "bits2num",
			|region: Region<'_, F>| {
				let mut ctx = RegionCtx::new(region, 0);
				let mut lc1 = ctx.assign_from_constant(common.advice[2], F::zero())?;
				let mut e2 = ctx.assign_from_constant(common.advice[1], F::one())?;

				let mut bits = Vec::new();
				for i in 0..self.bits.len() {
					ctx.enable(selector.clone())?;

					let bit = ctx.assign_advice(common.advice[0], self.bits[i].clone())?;
					bits.push(bit.clone());

					let cond_e2 = bit.value().cloned() * e2.value().cloned();
					let next_lc1 = lc1.value().cloned() + cond_e2;
					let next_e2 = e2.value().cloned() + e2.value();

					ctx.next();
					e2 = ctx.assign_advice(common.advice[1], next_e2)?;
					lc1 = ctx.assign_advice(common.advice[2], next_lc1)?;
				}
				ctx.constrain_equal(self.value.clone(), lc1.clone())?;

				Ok(bits)
			},
		)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		utils::{generate_params, prove_and_verify},
		CommonConfig,
	};
	use halo2::{
		circuit::SimpleFloorPlanner,
		dev::MockProver,
		halo2curves::bn256::{Bn256, Fr},
		plonk::Circuit,
	};

	#[derive(Clone)]
	struct TestConfig {
		common: CommonConfig,
		bits2num_selector: Selector,
	}

	#[derive(Clone)]
	struct TestCircuit<const B: usize> {
		numba: Fr,
		bytes: [u8; 32],
	}

	impl<const B: usize> TestCircuit<B> {
		fn new(x: Fr, y: [u8; 32]) -> Self {
			Self { numba: x, bytes: y }
		}
	}

	impl<const B: usize> Circuit<Fr> for TestCircuit<B> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			let common = CommonConfig::new(meta);
			let bits2num_selector = Bits2NumChip::configure(&common, meta);

			TestConfig { common, bits2num_selector }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let numba = layouter.assign_region(
				|| "temp",
				|region: Region<'_, Fr>| {
					let mut ctx = RegionCtx::new(region, 0);
					let numba_val = Value::known(self.numba);
					ctx.assign_advice(config.common.advice[0], numba_val)
				},
			)?;

			let bits = to_bits::<B>(self.bytes).map(|b| Fr::from(b));
			let bits2num = Bits2NumChip::new(numba, bits.to_vec());
			let _ = bits2num.synthesize(
				&config.common,
				&config.bits2num_selector,
				layouter.namespace(|| "bits2num"),
			)?;

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

		let circuit = TestCircuit::<256>::new(numba, numba_bytes);
		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();

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

		let circuit = TestCircuit::<256>::new(numba, numba_bytes);
		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_bits_to_num_big_plus() {
		// Testing biggest value in the field + 1.
		let numba_bytes = [
			1, 0, 0, 240, 147, 245, 225, 67, 145, 112, 185, 121, 72, 232, 51, 40, 93, 88, 129, 129,
			182, 69, 80, 184, 41, 160, 49, 225, 114, 78, 100, 48,
		];

		let circuit = TestCircuit::<256>::new(Fr::zero(), numba_bytes);
		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_bits_to_num_zero_bits() {
		// Testing zero as value with 0 bits.
		let circuit = TestCircuit::<0>::new(Fr::zero(), [0; 32]);
		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_bits_to_num_zero_value() {
		// Testing zero as value with 254 bits.
		let circuit = TestCircuit::<254>::new(Fr::zero(), [0; 32]);
		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_bits_to_num_production() {
		let numba = Fr::from(1311768467294899695u64);
		let numba_bytes = [
			239, 205, 171, 144, 120, 86, 52, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0,
		];

		let circuit = TestCircuit::<256>::new(numba, numba_bytes);
		let k = 9;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[&[]], rng).unwrap();

		assert!(res);
	}
}
