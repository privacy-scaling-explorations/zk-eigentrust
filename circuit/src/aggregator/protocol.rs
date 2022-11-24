use halo2wrong::{
	curves::group::{ff::PrimeField, Curve},
	halo2::plonk::Expression,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rotation(pub i32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Query {
	pub poly: usize,
	pub rotation: Rotation,
}

#[derive(Clone, Debug)]
pub struct Domain<F: PrimeField> {
	pub k: usize,
	pub n: usize,
	pub n_inv: F,
	pub gen: F,
	pub gen_inv: F,
}

#[derive(Clone, Debug)]
pub struct Protocol<C: Curve> {
	pub zk: bool,
	pub domain: Domain<C::Scalar>,
	pub preprocessed: Vec<C>,
	pub num_statement: Vec<usize>,
	pub num_auxiliary: Vec<usize>,
	pub num_challenge: Vec<usize>,
	pub evaluations: Vec<Query>,
	pub queries: Vec<Query>,
	pub relations: Vec<Expression<C::Scalar>>,
	pub transcript_initial_state: C::Scalar,
	pub accumulator_indices: Option<Vec<Vec<(usize, usize)>>>,
}
