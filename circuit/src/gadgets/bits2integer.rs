use super::bits2num::Bits2NumChip;
use crate::{
	integer::AssignedInteger, params::rns::RnsParams, Chip, Chipset, CommonConfig, FieldExt,
};
use halo2::{
	circuit::{AssignedCell, Layouter},
	plonk::{Error, Selector},
};

/// Bits2IntegerChipsetConfig structure.
#[derive(Debug, Clone)]
pub struct Bits2IntegerChipsetConfig {
	bits2num: Selector,
}

impl Bits2IntegerChipsetConfig {
	/// Construct a new config.
	pub fn new(bits2num: Selector) -> Self {
		Self { bits2num }
	}
}

/// Bits2IntegerChipset structure.
#[derive(Clone)]
pub struct Bits2IntegerChipset<
	W: FieldExt,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Assigned Integer variable.
	assigned_integer: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	Bits2IntegerChipset<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Creates a new chipset.
	pub fn new(assigned_integer: AssignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>) -> Self {
		Self { assigned_integer }
	}
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P> Chipset<N>
	for Bits2IntegerChipset<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	type Config = Bits2IntegerChipsetConfig;
	type Output = Vec<AssignedCell<N, N>>;

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<N>,
	) -> Result<Self::Output, Error> {
		let mut bits = Vec::new();
		for i in 0..NUM_LIMBS {
			let limb_bits_chip =
				Bits2NumChip::new_exact::<NUM_BITS>(self.assigned_integer.limbs[i].clone());
			let limb_bits = limb_bits_chip.synthesize(
				common,
				&config.bits2num,
				layouter.namespace(|| "limb bits"),
			)?;
			bits.extend(limb_bits);
		}

		Ok(bits)
	}
}

#[cfg(test)]
mod test {
	use std::str::FromStr;

	use super::*;
	use crate::integer::UnassignedInteger;
	use crate::params::rns::bn256::Bn256_4_68;
	use crate::RegionCtx;
	use crate::{
		integer::native::Integer,
		utils::{generate_params, prove_and_verify},
		CommonConfig, UnassignedValue,
	};
	use halo2::circuit::Region;
	use halo2::{
		circuit::SimpleFloorPlanner,
		dev::MockProver,
		halo2curves::bn256::{Bn256, Fq, Fr},
		plonk::{Circuit, ConstraintSystem},
	};
	use num_bigint::BigUint;

	type W = Fq;
	type N = Fr;
	const NUM_LIMBS: usize = 4;
	const NUM_BITS: usize = 68;
	type P = Bn256_4_68;

	#[derive(Clone)]
	struct TestConfig {
		common: CommonConfig,
		bits2integer: Bits2IntegerChipsetConfig,
	}

	#[derive(Clone)]
	struct TestCircuit {
		unassigned_integer: UnassignedInteger<W, N, NUM_LIMBS, NUM_BITS, P>,
	}

	impl TestCircuit {
		fn new(integer: Integer<W, N, NUM_LIMBS, NUM_BITS, P>) -> Self {
			Self { unassigned_integer: UnassignedInteger::from(integer) }
		}
	}

	impl Circuit<N> for TestCircuit {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { unassigned_integer: UnassignedInteger::without_witnesses() }
		}

		fn configure(meta: &mut ConstraintSystem<N>) -> TestConfig {
			let common = CommonConfig::new(meta);
			let bits2integer_selector = Bits2NumChip::configure(&common, meta);
			let bits2integer = Bits2IntegerChipsetConfig::new(bits2integer_selector);

			TestConfig { common, bits2integer }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<N>,
		) -> Result<(), Error> {
			let assigned_limbs = layouter.assign_region(
				|| "temp",
				|region: Region<'_, N>| {
					let mut ctx = RegionCtx::new(region, 0);
					let mut assigned_limbs: [Option<AssignedCell<N, N>>; NUM_LIMBS] =
						[(); NUM_LIMBS].map(|_| None);
					for i in 0..NUM_LIMBS {
						let x = ctx.assign_advice(
							config.common.advice[i], self.unassigned_integer.limbs[i],
						)?;
						assigned_limbs[i] = Some(x);
					}
					Ok(assigned_limbs)
				},
			)?;

			let assigned_integer = AssignedInteger::new(
				self.unassigned_integer.integer.clone(),
				assigned_limbs.map(|x| x.unwrap()),
			);

			let bits2integer = Bits2IntegerChipset::new(assigned_integer);
			let _ = bits2integer.synthesize(
				&config.common,
				&config.bits2integer,
				layouter.namespace(|| "bits2integer"),
			)?;

			Ok(())
		}
	}

	#[test]
	fn test_bits_to_integer() {
		// Testing field element 0x1.
		let numba_big = BigUint::from_str("1").unwrap();
		let numba = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(numba_big);

		let circuit = TestCircuit::new(numba);
		let k = 8;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_bits_to_integer_big() {
		// Testing biggest value in the field.
		let numba_big = BigUint::from_str(
			"21888242871839275222246405745257275088548364400416034343698204186575808495616",
		)
		.unwrap();
		let numba = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(numba_big);

		let circuit = TestCircuit::new(numba);
		let k = 8;
		let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_bits_to_integer_production() {
		let numba_big = BigUint::from_str("3823613239503432837285398709123").unwrap();
		let numba = Integer::<W, N, NUM_LIMBS, NUM_BITS, P>::new(numba_big);
		let circuit = TestCircuit::new(numba);
		let k = 8;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, circuit, &[&[]], rng).unwrap();

		assert!(res);
	}
}
