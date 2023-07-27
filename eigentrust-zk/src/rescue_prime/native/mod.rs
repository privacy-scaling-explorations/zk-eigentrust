/// Native sponge implementation
pub mod sponge;

use crate::{params::hasher::RoundParams, FieldExt, Hasher};
use std::marker::PhantomData;

/// Constructs objects.
pub struct RescuePrime<F: FieldExt, const WIDTH: usize, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Constructs an array for the inputs.
	inputs: [F; WIDTH],
	/// Constructs a phantom data for the parameters.
	_params: PhantomData<P>,
}

impl<F: FieldExt, const WIDTH: usize, P> RescuePrime<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Create the objects.
	pub fn new(inputs: [F; WIDTH]) -> Self {
		RescuePrime { inputs, _params: PhantomData }
	}

	/// Rescue Prime permutation
	pub fn permute(&self) -> [F; WIDTH] {
		let full_rounds = P::full_rounds();
		let round_constants = P::round_constants();

		let mut state = self.inputs;
		for i in 0..full_rounds - 1 {
			// Apply Sbox
			for state in state.iter_mut().take(WIDTH) {
				*state = P::sbox_f(*state);
			}
			// Apply MDS
			state = P::apply_mds(&state);
			// Apply round constants
			let consts = P::load_round_constants(i, &round_constants);
			state = P::apply_round_constants(&state, &consts);
			// Apply Sbox inverse
			for state in state.iter_mut().take(WIDTH) {
				*state = P::sbox_inv_f(*state);
			}
			// Apply MDS for the second time
			state = P::apply_mds(&state);
			// Apply next round constants
			let consts = P::load_round_constants(i + 1, &round_constants);
			state = P::apply_round_constants(&state, &consts);
		}

		state
	}
}

impl<F: FieldExt, const WIDTH: usize, P> Hasher<F, WIDTH> for RescuePrime<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	fn new(inputs: [F; WIDTH]) -> Self {
		Self::new(inputs)
	}

	fn finalize(&self) -> [F; WIDTH] {
		Self::permute(self)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::params::hasher::{hex_to_field, rescue_prime_bn254_5x5::Params};
	use halo2::halo2curves::bn256::Fr;

	type TestHasher = RescuePrime<Fr, 5, Params>;

	#[test]
	fn test_native_rescue_prime_5x5() {
		// Testing 5x5 input.
		let inputs: [Fr; 5] = [
			"0x0000000000000000000000000000000000000000000000000000000000000000",
			"0x0000000000000000000000000000000000000000000000000000000000000001",
			"0x0000000000000000000000000000000000000000000000000000000000000002",
			"0x0000000000000000000000000000000000000000000000000000000000000003",
			"0x0000000000000000000000000000000000000000000000000000000000000004",
		]
		.map(|n| hex_to_field(n));

		// Results taken from https://github.com/matter-labs/rescue-poseidon
		let outputs: [Fr; 5] = [
			"0x1a06ea09af4d8d61f991846f001ded4056feafcef55f1e9c4fd18100b8c7654f",
			"0x2f66d057b2bd9692f51e072013b8f320c5e6d7081070ffe7ca357e18e5faecf4",
			"0x177abf3b6a2e903adf4c71f18f744b55b39c487a9a4fd1a1d4aee381b99f357b",
			"0x1271bfa104c298efaccc1680be1b6e36cbf2c87ea789f2f79f7742bc16992235",
			"0x040f785abfad4da68331f9c884343fa6eecb07060ebcd96117862acebae5c3ac",
		]
		.map(|n| hex_to_field(n));

		let rescue_prime = TestHasher::new(inputs);

		let out = rescue_prime.permute();

		assert_eq!(out, outputs);
	}
}
