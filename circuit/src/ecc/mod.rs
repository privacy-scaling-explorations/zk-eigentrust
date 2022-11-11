/// Native version of the chip
pub mod native;

use std::marker::PhantomData;

use crate::{
	gadgets::bits2num::{Bits2NumChip, Bits2NumConfig},
	integer::{native::ReductionWitness, rns::RnsParams, IntegerChip, IntegerConfig},
};
use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};

struct EccConfig<const NUM_LIMBS: usize> {
	bits2num: Bits2NumConfig,
	integer: IntegerConfig<NUM_LIMBS>,
}

struct EccChip<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Constructs phantom datas for the variables.
	_native: PhantomData<N>,
	_wrong: PhantomData<W>,
	_rns: PhantomData<P>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	EccChip<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<N>) -> EccConfig<NUM_LIMBS> {
		const BITS: usize = 256;
		let bits2num = Bits2NumChip::<N, BITS>::configure(meta);
		let integer = IntegerChip::<W, N, NUM_LIMBS, NUM_BITS, P>::configure(meta);

		EccConfig { bits2num, integer }
	}

	pub fn add(
		// Assigns a cell for the r_x.
		r_x: [AssignedCell<N, N>; NUM_LIMBS],
		// Assigns a cell for the r_y.
		r_y: [AssignedCell<N, N>; NUM_LIMBS],
		// Reduction witness for r -- make sure r is in the W field before being passed
		r_rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
		// Assigns a cell for the e_x.
		e_x: [AssignedCell<N, N>; NUM_LIMBS],
		// Assigns a cell for the e_y.
		e_y: [AssignedCell<N, N>; NUM_LIMBS],
		// Reduction witness for `e` -- make sure `e` is in the W field before being passed
		e_rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
		// Reduction witnesses for add operation
		reduction_witnesess: Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>,
		// Ecc config columns
		config: EccConfig<NUM_LIMBS>,
		// Layouter
		mut layouter: impl Layouter<N>,
	) -> Result<
		(
			[AssignedCell<N, N>; NUM_LIMBS],
			[AssignedCell<N, N>; NUM_LIMBS],
		),
		Error,
	> {
		// Assign a region where we use columns from Integer chip
		// sub selector - row 0
		// sub selector - row 1
		// div selector - row 2
		// mul selector - row 3
		// sub selector - row 4
		// sub selector - row 5
		// sub selector - row 6
		// mul selector - row 7
		// sub selector - row 8
		Err(Error::Synthesis)
	}

	pub fn double(
		// Assigns a cell for the r_x.
		r_x: [AssignedCell<N, N>; NUM_LIMBS],
		// Assigns a cell for the r_y.
		r_y: [AssignedCell<N, N>; NUM_LIMBS],
		// Reduction witness for r -- make sure r is in the W field before being passed
		r_rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
		// Ecc Config
		config: EccConfig<NUM_LIMBS>,
		// Layouter
		mut layouter: impl Layouter<N>,
	) -> Result<
		(
			[AssignedCell<N, N>; NUM_LIMBS],
			[AssignedCell<N, N>; NUM_LIMBS],
		),
		Error,
	> {
		// add selector - row 0
		// mul selector - row 1
		// mul3 selector - row 2
		// div selector - row 3
		// add selector - row 4
		// mul selector - row 5
		// sub selector - row 6
		// sub selector - row 7
		// mul selector - row 8
		// sub selector - row 9
		Err(Error::Synthesis)
	}

	pub fn mul_scalar(
		// Assigns a cell for the r_x.
		r_x: [AssignedCell<N, N>; NUM_LIMBS],
		// Assigns a cell for the r_y.
		r_y: [AssignedCell<N, N>; NUM_LIMBS],
		// Reduction witness for r -- make sure r is in the W field before being passed
		r_rw: ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>,
		// Assigns a cell for the value.
		value: AssignedCell<N, N>,
		// Constructs an array for the value bits.
		value_bits: Vec<N>,
		// Reduction witnesses for mul scalar operation
		reduction_witnesess: Vec<ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P>>,
		// Ecc Config
		config: EccConfig<NUM_LIMBS>,
		// Layouter
		mut layouter: impl Layouter<N>,
	) -> Result<
		(
			[AssignedCell<N, N>; NUM_LIMBS],
			[AssignedCell<N, N>; NUM_LIMBS],
		),
		Error,
	> {
		// Check that `value_bits` are decomposed from `value`
		// for i in 0..value_bits.len() {
		//    if value_bits[i] == 1 {
		//        add selector - row i
		//    }
		//    double selector - row i
		// }
		Err(Error::Synthesis)
	}
}

#[cfg(test)]
mod test {
	#[test]
	fn should_add_two_points() {}

	#[test]
	fn should_double_a_point() {}

	#[test]
	fn should_mul_with_scalar() {}
}
