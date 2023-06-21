use crate::{
	integer::AssignedInteger, params::rns::RnsParams, Chip, Chipset, CommonConfig, FieldExt,
};
use halo2::{
	circuit::{AssignedCell, Layouter},
	plonk::{Error, Selector},
};

use super::bits2num::Bits2NumChip;

/// Bits2IntegerChipsetConfig
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

/// Constructs a cell and a variable for the circuit.
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
	/// Create a new chip.
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
	type Output = [Vec<AssignedCell<N, N>>; NUM_LIMBS];

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<N>,
	) -> Result<Self::Output, Error> {
		let mut bits = [(); NUM_LIMBS].map(|_| None);
		for i in 0..NUM_LIMBS {
			let limb_bits = Bits2NumChip::new(self.assigned_integer.limbs[i].clone());
			bits[i] = Some(limb_bits.synthesize(
				common,
				&config.bits2num,
				layouter.namespace(|| "limb bits"),
			)?);
		}
		Ok(bits.map(|x| x.unwrap()))
	}
}
