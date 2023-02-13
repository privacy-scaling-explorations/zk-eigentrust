use crate::rescue_prime::{native::RescuePrime, RoundParams};
use halo2::arithmetic::FieldExt;
use std::marker::PhantomData;

/// Constructs objects.
pub struct RescuePrimeSponge<F: FieldExt, const WIDTH: usize, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Constructs a vector for the inputs.
	inputs: Vec<F>,
	/// Internal state
	state: [F; WIDTH],
	/// Constructs a phantom data for the parameters.
	_params: PhantomData<P>,
}

impl<F: FieldExt, const WIDTH: usize, P> RescuePrimeSponge<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Create objects.
	pub fn new() -> Self {
		Self { inputs: Vec::new(), state: [F::zero(); WIDTH], _params: PhantomData }
	}

	/// Clones and appends all elements from a slice to the vec.
	pub fn update(&mut self, inputs: &[F]) {
		self.inputs.extend_from_slice(inputs);
	}

	/// Absorb the data in and split it into
	/// chunks of size WIDTH.
	pub fn load_state(chunk: &[F]) -> [F; WIDTH] {
		assert!(chunk.len() <= WIDTH);
		let mut fixed_chunk = [F::zero(); WIDTH];
		fixed_chunk[..chunk.len()].copy_from_slice(chunk);
		fixed_chunk
	}

	/// Squeeze the data out by
	/// permuting until no more chunks are left
	pub fn squeeze(&mut self) -> F {
		assert!(!self.inputs.is_empty());

		for chunk in self.inputs.chunks(WIDTH) {
			let loaded_state = Self::load_state(chunk);
			let input = loaded_state.zip(self.state).map(|(lhs, rhs)| lhs + rhs);

			let rescue_prime = RescuePrime::<_, WIDTH, P>::new(input);
			self.state = rescue_prime.permute();
		}

		// Clear the inputs, and return the result
		self.inputs.clear();
		self.state[0]
	}
}
