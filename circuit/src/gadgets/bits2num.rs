use crate::{
	utils::{assigned_to_field, field_to_bits, field_to_bits_vec},
	Chip, CommonConfig, FieldExt, RegionCtx,
};
use halo2::{
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};

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
	pub fn new_exact<const B: usize>(value: AssignedCell<F, F>) -> Self {
		let fe = assigned_to_field(value.clone());
		let bits = field_to_bits::<_, B>(fe);
		let bit_vals = bits.map(|x| Value::known(x)).to_vec();
		Self { value, bits: bit_vals }
	}

	/// Create a new chip.
	pub fn new(value: AssignedCell<F, F>) -> Self {
		let fe = assigned_to_field(value.clone());
		let bit_vals = field_to_bits_vec(fe).iter().map(|&x| Value::known(x)).collect();
		Self { value, bits: bit_vals }
	}
}

impl<F: FieldExt> Chip<F> for Bits2NumChip<F> {
	type Output = Vec<AssignedCell<F, F>>;

	/// Make the circuit config.
	fn configure(common: &CommonConfig, meta: &mut ConstraintSystem<F>) -> Selector {
		let selector = meta.selector();

		meta.create_gate("bits2num", |v_cells| {
			//
			// Gate config
			//
			// | selector |   0    |    1    |    2     |      3     |    4    |    5     |
			// |----------|--------|---------|----------|------------|---------|----------|
			// |    *     | bit[i] |    e2   |   lc1    | bit[i + 1] |    e2   |   lc1    |
			// |          |        | e2_next | lc1_next |            |         |          |
			//
			// NOTE: Current chip config & synthesize is based on assumption that
			//       the length of `bits` is even number.
			//
			//		 bits.len() % 2 == 0

			//
			// Example: value = 13 (1101)
			//			bits = 1011 (little-endian order)
			//
			// | selector |   0    |    1    |    2     |     3      |    4    |    5     |
			// |----------|--------|---------|----------|------------|---------|----------|
			// |    *     |   1    |    1    |    0     |     0      |    2    |    1     |
			// |    *     |   1    |    4    |    1     |     1      |    8    |    5     |
			// |          |        |    16   |    13    |            |         |          |
			//
			// Original, more intelligible config example
			//
			// | selector |   0    |    1    |    2     |
			// |----------|--------|---------|----------|
			// |    *     |   1    |    1    |    0     |
			// |    *     |   0    |    2    |    1     |
			// |    *     |   1    |    4    |    1     |
			// |    *     |   1    |    8    |    5     |
			// |          |        |    16   |    13    |
			//

			let one_exp = Expression::Constant(F::ONE);

			let bit_i_exp = v_cells.query_advice(common.advice[0], Rotation::cur());
			let e2_i_exp = v_cells.query_advice(common.advice[1], Rotation::cur());
			let lc1_i_exp = v_cells.query_advice(common.advice[2], Rotation::cur());

			let bit_i_1_exp = v_cells.query_advice(common.advice[3], Rotation::cur());
			let e2_i_1_exp = v_cells.query_advice(common.advice[4], Rotation::cur());
			let lc1_i_1_exp = v_cells.query_advice(common.advice[5], Rotation::cur());

			let e2_next_exp = v_cells.query_advice(common.advice[1], Rotation::next());
			let lc1_next_exp = v_cells.query_advice(common.advice[2], Rotation::next());

			let s_exp = v_cells.query_selector(selector);

			vec![
				// bit * (1 - bit) == 0
				// Constraining bit to be a boolean.
				s_exp.clone() * (bit_i_exp.clone() * (one_exp.clone() - bit_i_exp.clone())),
				s_exp.clone() * (bit_i_1_exp.clone() * (one_exp - bit_i_1_exp.clone())),
				// e2 + e2 == e2_next
				// Starting from 1, doubling.
				s_exp.clone() * ((e2_i_exp.clone() + e2_i_exp.clone()) - e2_i_1_exp.clone()),
				s_exp.clone() * ((e2_i_1_exp.clone() + e2_i_1_exp.clone()) - e2_next_exp.clone()),
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
				s_exp.clone() * ((bit_i_exp * e2_i_exp + lc1_i_exp) - lc1_i_1_exp.clone()),
				s_exp * ((bit_i_1_exp * e2_i_1_exp + lc1_i_1_exp) - lc1_next_exp),
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
				let mut lc1 = ctx.assign_from_constant(common.advice[2], F::ZERO)?;
				let mut e2 = ctx.assign_from_constant(common.advice[1], F::ONE)?;

				let mut res_bits = Vec::new();

				// If the length of `self.bits` is odd, we add extra zero at the end.
				// It does not affect the proval since the most significant bit(last element of bits) becomes zero.
				let mut input_bits = self.bits.clone();
				if self.bits.len() % 2 == 1 {
					input_bits.push(Value::known(F::ZERO));
				}
				for i in (0..input_bits.len()).step_by(2) {
					ctx.enable(*selector)?;

					// assign `bits[i]` & compute next values
					let bit_i = ctx.assign_advice(common.advice[0], input_bits[i])?;

					let lc1_i_1 =
						lc1.value().cloned() + bit_i.value().cloned() * e2.value().cloned();
					let e2_i_1 = e2.value().cloned() + e2.value();

					// assign `bits[i + 1]` & compute next values
					let bit_i_1 = ctx.assign_advice(common.advice[3], input_bits[i + 1])?;
					let e2_i_1 = ctx.assign_advice(common.advice[4], e2_i_1)?;
					let lc1_1 = ctx.assign_advice(common.advice[5], lc1_i_1)?;

					let lc1_next =
						lc1_1.value().cloned() + bit_i_1.value().cloned() * e2_i_1.value().cloned();
					let e2_next = e2_i_1.value().cloned() + e2_i_1.value();

					res_bits.push(bit_i.clone());
					res_bits.push(bit_i_1.clone());

					ctx.next();
					e2 = ctx.assign_advice(common.advice[1], e2_next)?;
					lc1 = ctx.assign_advice(common.advice[2], lc1_next)?;
				}
				ctx.constrain_equal(self.value.clone(), lc1)?;

				// If the length of `self.bits` is odd, it means that we have added extra zero at the end of bits.
				// Hence, we should pop the last bit element.
				if self.bits.len() % 2 == 1 {
					res_bits.pop();
				}

				Ok(res_bits)
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
		numba: Value<Fr>,
	}

	impl<const B: usize> TestCircuit<B> {
		fn new(x: Fr) -> Self {
			Self { numba: Value::known(x) }
		}
	}

	impl<const B: usize> Circuit<Fr> for TestCircuit<B> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { numba: Value::unknown() }
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
					ctx.assign_advice(config.common.advice[0], self.numba)
				},
			)?;

			let bits2num = Bits2NumChip::new_exact::<B>(numba);
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

		let circuit = TestCircuit::<256>::new(numba);
		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_bits_to_num_big() {
		// Testing biggest value in the field.
		let numba = Fr::zero().sub(&Fr::one());

		let circuit = TestCircuit::<256>::new(numba);
		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_bits_to_num_big_plus() {
		// Testing biggest value in the field + 1.
		let circuit = TestCircuit::<256>::new(Fr::zero());
		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_bits_to_num_zero_bits() {
		// Testing zero as value with 0 bits.
		let circuit = TestCircuit::<0>::new(Fr::zero());
		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_bits_to_num_zero_value() {
		// Testing zero as value with 254 bits.
		let circuit = TestCircuit::<254>::new(Fr::zero());
		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_bits_to_num_production() {
		let numba = Fr::from(1311768467294899695u64);
		let circuit = TestCircuit::<256>::new(numba);
		let k = 9;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[&[]], rng).unwrap();

		assert!(res);
	}
}
