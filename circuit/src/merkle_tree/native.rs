use std::marker::PhantomData;

use halo2wrong::halo2::arithmetic::FieldExt;
use num_traits::pow;

use crate::{
	params::RoundParams,
	poseidon::native::{sponge::PoseidonSponge, Poseidon},
};
const WIDTH: usize = 5;

#[derive(Clone, Debug)]
struct MerkleTree<F: FieldExt, P>
where
	P: RoundParams<F, WIDTH>,
{
	_params: PhantomData<P>,
	root: Option<F>,
	nodes: Vec<Option<F>>,
	height: usize,
	first_leaf_index: usize,
}

#[derive(Clone)]
struct Path<F: FieldExt, P>
where
	P: RoundParams<F, WIDTH>,
{
	_params: PhantomData<P>,
	value: F,
	path_vec: Vec<F>,
}

impl<F: FieldExt, P> MerkleTree<F, P>
where
	P: RoundParams<F, WIDTH>,
{
	fn new(height: usize) -> Self {
		// An array starts from index 0, that is why we do -1 operation to find the
		// first leaf index.
		let first_leaf_index = pow(2, height) - 1;
		// Calculating number of nodes is basically 2n - 1 (n is number of leaves)
		let num_nodes = pow(2, height + 1) - 1;
		let nodes = vec![None; num_nodes];
		MerkleTree { _params: PhantomData, root: None, nodes, height, first_leaf_index }
	}

	fn add_leaves(&mut self, values: Vec<F>) -> &Self {
		for i in 0..values.len() {
			self.nodes[self.first_leaf_index + i] = Some(values[i]);
		}
		self
	}

	fn build_tree(&mut self) -> &Self {
		if self.height > 0 {
			let mut new_tree = MerkleTree::<F, P>::new(self.height - 1);
			let first_leaf_index = (new_tree.first_leaf_index * 2) + 1;
			let mut hash = Vec::new();
			for i in 0..first_leaf_index {
				if i % 2 == 0 {
					let hasher: Poseidon<F, WIDTH, P> = Poseidon::new([
						self.nodes[first_leaf_index + i].unwrap(),
						self.nodes[first_leaf_index + i + 1].unwrap(),
						F::zero(),
						F::zero(),
						F::zero(),
					]);
					let hashes = hasher.permute();

					hash.push(hashes[0] + hashes[1]);
				}
			}
			new_tree.add_leaves(hash.clone());
			for i in new_tree.first_leaf_index..new_tree.nodes.len() {
				self.nodes[i] = new_tree.nodes[i];
			}
			self.height = new_tree.height;
			self.build_tree();
			self.height += 1;
		}
		self.root = self.nodes[0];
		self
	}

	fn find_path(&mut self, value: F) -> Path<F, P> {
		let mut value_index = None;
		for i in (self.first_leaf_index - 1)..self.nodes.len() {
			if value == self.nodes[i].unwrap() {
				value_index = Some(i);
				break;
			}
		}

		let mut path_vec: Vec<F> = Vec::new();
		let mut j = value_index.unwrap();
		// Childs for a parent node is 2n and 2n - 1.
		// Reverse is (n / 2) and (n / 2 - 1).
		for i in 0..self.height {
			if j % 2 == 0 {
				path_vec.push(self.nodes[j - 1].unwrap());
				path_vec.push(self.nodes[j].unwrap());
				j = j / 2 - 1;
			} else {
				path_vec.push(self.nodes[j].unwrap());
				path_vec.push(self.nodes[j + 1].unwrap());
				j = j / 2;
			}
		}
		path_vec.push(self.root.unwrap());
		Path { path_vec, value, _params: PhantomData }
	}
}

impl<F: FieldExt, P> Path<F, P>
where
	P: RoundParams<F, WIDTH>,
{
	fn verify(&self) -> bool {
		let mut is_satisfied = true;
		for i in 0..self.path_vec.len() - 2 {
			if i % 2 == 0 {
				let hasher: Poseidon<F, WIDTH, P> = Poseidon::new([
					self.path_vec[i],
					self.path_vec[i + 1],
					F::zero(),
					F::zero(),
					F::zero(),
				]);
				let hashes = hasher.permute();
				is_satisfied = is_satisfied | self.path_vec.contains(&(hashes[0] + hashes[1]));
			}
		}
		is_satisfied
	}
}

#[cfg(test)]
mod test {
	use crate::params::poseidon_bn254_5x5::Params;
	use halo2wrong::{curves::bn256::Fr, halo2::arithmetic::Field};
	use rand::thread_rng;

	use super::MerkleTree;

	#[test]
	fn should_build_tree_and_find_path() {
		let rng = &mut thread_rng();
		let mut merkle = MerkleTree::<Fr, Params>::new(3);
		let value = Fr::random(rng.clone());
		merkle.add_leaves(vec![
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			value,
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
		]);
		merkle.build_tree();
		let path = merkle.find_path(value);
		assert!(path.verify());
		assert_eq!(path.path_vec[6], merkle.root.unwrap());
	}
}
