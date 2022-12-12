use std::marker::PhantomData;

use halo2wrong::halo2::arithmetic::FieldExt;

use crate::{params::RoundParams, poseidon::native::sponge::PoseidonSponge};

const WIDTH: usize = 5;

#[derive(Clone, Debug)]
struct MerkleTree<F: FieldExt, P>
where
	P: RoundParams<F, WIDTH>,
{
	_params: PhantomData<P>,
	root: Option<F>,
	indexes: Vec<Option<F>>,
	height: usize,
}

impl<F: FieldExt, P> MerkleTree<F, P>
where
	P: RoundParams<F, WIDTH>,
{
	fn new(height: usize) -> Self {
		let mut nodes = 1;
		for i in 0..(height + 1) {
			nodes = 2 * nodes;
		}
		let indexes = vec![None; nodes - 1];
		MerkleTree { _params: PhantomData, root: None, indexes, height }
	}

	fn implement_leaves(mut self: MerkleTree<F, P>, values: Vec<F>) -> Self {
		let mut leaves = 1;
		for i in 0..(self.height) {
			leaves = 2 * leaves;
		}
		for i in 0..values.len() {
			self.indexes[leaves - 1 + i] = Some(values[i]);
		}
		self
	}

	fn build_tree(self: &mut MerkleTree<F, P>, height: usize) -> &Self {
		let mut hasher: PoseidonSponge<F, WIDTH, P> = PoseidonSponge::new();
		if height > 0 {
			let mut new_tree = MerkleTree::<F, P>::new(height - 1);
			let mut leaves = 1;
			for i in 0..height {
				leaves = 2 * leaves;
			}
			let leaves_new = leaves / 2;
			let mut step_by_two = 0;
			let mut hash = Vec::new();
			for i in 0..leaves - 1 {
				if step_by_two % 2 == 0 {
					hasher.update(&[self.indexes[leaves + i - 1].unwrap()]);
					hasher.update(&[self.indexes[leaves + i].unwrap()]);
					hash.push(hasher.squeeze());
				}
				step_by_two += 1;
			}
			new_tree = new_tree.implement_leaves(hash.clone());
			for i in leaves_new - 1..new_tree.indexes.len() {
				self.indexes[i] = new_tree.indexes[i];
			}
			self.build_tree(new_tree.height);
		}
		self.root = self.indexes[0];
		self
	}

	fn find_path() {}
}

#[cfg(test)]
mod test {
	use crate::params::poseidon_bn254_5x5::Params;
	use halo2wrong::{curves::bn256::Fr, halo2::arithmetic::Field};

	use super::MerkleTree;

	#[test]
	fn should_build_tree() {
		let mut merkle = MerkleTree::<Fr, Params>::new(5);
		merkle = merkle
			.implement_leaves([(); 32].map(|_| <Fr as Field>::random(rand::thread_rng())).to_vec());
		merkle.build_tree(merkle.height);
		//println!("{:#?}", merkle.root);
	}
}
