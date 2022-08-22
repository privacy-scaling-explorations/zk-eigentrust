use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};

pub fn to_bits(num: [u8; 32]) -> [bool; 256] {
	let mut bits = [false; 256];
	for i in 0..256 {
		bits[i] = num[i / 8] & (1 << (i % 8)) != 0;
	}
	bits
}

#[derive(Clone)]
pub struct Bits2NumConfig {
	pub bits: Column<Advice>,
	lc1: Column<Advice>,
	e2: Column<Advice>,
	selector: Selector,
}

#[derive(Clone)]
pub struct Bits2NumChip<F: FieldExt> {
	value: AssignedCell<F, F>,
	bits: [Value<F>; 256],
}

impl<F: FieldExt> Bits2NumChip<F> {
	pub fn new(value: AssignedCell<F, F>, bits: [F; 256]) -> Self {
		Self {
			value,
			bits: bits.map(|b| Value::known(b)),
		}
	}
}

impl<F: FieldExt> Bits2NumChip<F> {
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
				// bit * (1 - bit) == 0 (bit is boolean)
				s_exp.clone() * (bit_exp.clone() * (one_exp - bit_exp.clone())),
				// e2 + e2 == e2_next
				s_exp.clone() * ((e2_exp.clone() + e2_exp.clone()) - e2_next_exp),
				// lc1 + bit * e2 == lc1_next
				s_exp * ((bit_exp * e2_exp + lc1_exp) - lc1_next_exp),
			]
		});

		Bits2NumConfig {
			bits,
			lc1,
			e2,
			selector: s,
		}
	}

	pub fn synthesize(
		&self,
		config: Bits2NumConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<[AssignedCell<F, F>; 256], Error> {
		layouter.assign_region(
			|| "bits2num",
			|mut region: Region<'_, F>| {
				let mut lc1 =
					region.assign_advice_from_constant(|| "lc1_0", config.lc1, 0, F::zero())?;
				let mut e2 =
					region.assign_advice_from_constant(|| "e2_0", config.e2, 0, F::one())?;

				let mut bits: [Option<AssignedCell<F, F>>; 256] = [(); 256].map(|_| None);
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
	struct TestCircuit {
		numba: Fr,
	}

	impl TestCircuit {
		fn new(x: Fr) -> Self {
			Self { numba: x }
		}
	}

	impl Circuit<Fr> for TestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> TestConfig {
			let bits2num = Bits2NumChip::configure(meta);
			let temp = meta.advice_column();

			meta.enable_equality(temp);

			TestConfig { bits2num, temp }
		}

		fn synthesize(
			&self,
			config: TestConfig,
			mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let numba = layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, Fr>| {
					region.assign_advice(|| "temp_x", config.temp, 0, || Value::known(self.numba))
				},
			)?;

			let bits = to_bits(self.numba.to_bytes()).map(|b| Fr::from(b));
			let bits2num = Bits2NumChip::new(numba, bits);
			let _ = bits2num.synthesize(config.bits2num, layouter.namespace(|| "bits2num"))?;
			Ok(())
		}
	}

	#[test]
	fn test_bits_to_num() {
		let numba = Fr::from(1311768467294899695u64);
		let circuit = TestCircuit::new(numba);

		let k = 9;
		let prover = MockProver::run(k, &circuit, vec![]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_bits_to_num_production() {
		let numba = Fr::from(1311768467294899695u64);
		let circuit = TestCircuit::new(numba);

		let k = 9;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[], rng).unwrap();

		assert!(res);
	}
}
