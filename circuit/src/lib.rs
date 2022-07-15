//! The module for the main EigenTrust circuit.

#![feature(array_try_map)]
#![feature(array_zip)]
#![allow(clippy::needless_range_loop)]

pub mod gadgets;
pub mod poseidon;
pub mod utils;

pub use halo2wrong;
use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{Layouter, SimpleFloorPlanner, Value},
	plonk::{Circuit, ConstraintSystem, Error},
};
use std::marker::PhantomData;

/// The halo2 columns config for the main circuit.
#[derive(Clone, Debug)]
pub struct EigenTrustConfig {}

/// The EigenTrust main circuit.
#[derive(Clone)]
pub struct EigenTrustCircuit<N: FieldExt, const SIZE: usize> {
	/// Opinions of peers j to the peer i (the prover).
	op_ji: [Value<N>; SIZE],
	/// Opinon from peer i (the prover) to the peer v (the verifyer).
	c_v: Value<N>,
	_marker: PhantomData<N>,
}

impl<N: FieldExt, const SIZE: usize> EigenTrustCircuit<N, SIZE> {
	/// Create a new EigenTrustCircuit.
	pub fn new(op_ji: [N; SIZE], c_v: N) -> Self {
		Self {
			op_ji: op_ji.map(|c| Value::known(c)),
			c_v: Value::known(c_v),
			_marker: PhantomData,
		}
	}
}

impl<N: FieldExt, const SIZE: usize> Circuit<N> for EigenTrustCircuit<N, SIZE> {
	type Config = EigenTrustConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self {
			op_ji: [Value::unknown(); SIZE],
			c_v: Value::unknown(),
			_marker: PhantomData,
		}
	}

	/// Make the circuit config.
	fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
		EigenTrustConfig {}
	}

	/// Synthesize the circuit.
	fn synthesize(
		&self,
		config: Self::Config,
		mut layouter: impl Layouter<N>,
	) -> Result<(), Error> {
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use halo2wrong::{
		curves::bn256::{Bn256, Fr},
		halo2::dev::MockProver,
	};
	use rand::thread_rng;
	use utils::{generate_params, prove_and_verify};

	const SIZE: usize = 12;

	fn to_wide(p: [u8; 32]) -> [u8; 64] {
		let mut res = [0u8; 64];
		res[..32].copy_from_slice(&p[..]);
		res
	}

	#[test]
	fn test_eigen_trust_verify() {
		let k = 18;
		let mut rng = thread_rng();

		// Data from neighbors of i
		let op_ji = [(); SIZE].map(|_| Fr::from_u128(1));
		let c_v = Fr::from_u128(1);

		let eigen_trust = EigenTrustCircuit::<_, SIZE>::new(op_ji, c_v);

		let prover = match MockProver::<Fr>::run(k, &eigen_trust, vec![vec![]]) {
			Ok(prover) => prover,
			Err(e) => panic!("{}", e),
		};

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_eigen_trust_production_prove_verify() {
		let k = 18;
		let mut rng = thread_rng();

		// Data from neighbors of i
		let op_ji = [(); SIZE].map(|_| Fr::from_u128(1));
		let c_v = Fr::from_u128(1);

		let eigen_trust = EigenTrustCircuit::<_, SIZE>::new(op_ji, c_v);

		let params = generate_params(k);
		prove_and_verify::<Bn256, _, _>(params, eigen_trust, &[&[]], &mut rng).unwrap();
	}
}
