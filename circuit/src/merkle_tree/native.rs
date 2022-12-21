use std::marker::PhantomData;

use halo2wrong::halo2::arithmetic::FieldExt;
use num_traits::pow;
use std::collections::HashMap;

use crate::{params::RoundParams, poseidon::native::Poseidon};
const WIDTH: usize = 5;

#[derive(Clone, Debug)]
/// MerkleTree structure
struct MerkleTree<F: FieldExt, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// HashMap to keep the level and index of the nodes
	nodes: HashMap<usize, Vec<F>>,
	/// Height of the tree
	height: usize,
	/// PhantomData for the params
	_params: PhantomData<P>,
}

impl<F: FieldExt, P> MerkleTree<F, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Build a MerkleTree from given leaf nodes and height
	fn build_tree(mut leaves: Vec<F>, height: usize) -> Self {
		assert!(leaves.len() <= pow(2, height));
		// 0th level is the leaf level and the max level is the root level
		let mut nodes = HashMap::new();
		// Assign zero to the leaf values if they are empty
		for i in leaves.len()..pow(2, height) {
			leaves.push(F::zero());
		}
		nodes.insert(0, leaves);

		for level in 0..height {
			let mut hashes = Vec::new();
			for i in 0..nodes[&level].len() {
				if i % 2 != 0 {
					continue;
				}
				let pos_inputs =
					[nodes[&level][i], nodes[&level][i + 1], F::zero(), F::zero(), F::zero()];
				let hasher: Poseidon<F, WIDTH, P> = Poseidon::new(pos_inputs);
				hashes.push(hasher.permute()[0]);
			}
			nodes.insert(level + 1, hashes);
		}
		MerkleTree { nodes, height, _params: PhantomData }
	}

	/// Find path for the given value to the root
	fn find_path(&mut self, value: F) -> Path<F, P> {
		//
		// TODO: This way of finding index will fail if we have same inputs
		//
		let mut value_index = self.nodes[&0].iter().position(|x| x == &value).unwrap();
		let mut path_vec: Vec<F> = Vec::new();
		// Childs for a parent node is 2n and 2n + 1.
		// value_index keeps index of that nodes in reverse order to apply this
		// algorithm.
		for level in 0..self.height {
			if value_index % 2 == 1 {
				path_vec.push(self.nodes[&level][value_index - 1]);
				path_vec.push(self.nodes[&level][value_index]);
			} else {
				path_vec.push(self.nodes[&level][value_index]);
				path_vec.push(self.nodes[&level][value_index + 1]);
			}
			value_index = value_index / 2;
		}
		path_vec.push(self.nodes[&self.height][0]);
		Path { path_vec, value, _params: PhantomData }
	}
}

#[derive(Clone)]
/// Path structure
struct Path<F: FieldExt, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Value that is based on for construction of the path
	value: F,
	/// Vector that keeps the path
	path_vec: Vec<F>,
	/// PhantomData for the params
	_params: PhantomData<P>,
}

impl<F: FieldExt, P> Path<F, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Sanity check for the path vector
	fn verify(&self) -> bool {
		let mut is_satisfied = true;
		for i in 0..self.path_vec.len() - 1 {
			if i % 2 != 0 {
				continue;
			}
			let pos_inputs =
				[self.path_vec[i], self.path_vec[i + 1], F::zero(), F::zero(), F::zero()];
			let hasher: Poseidon<F, WIDTH, P> = Poseidon::new(pos_inputs);
			is_satisfied = is_satisfied | self.path_vec.contains(&(hasher.permute()[0]));
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
		// Testing build_tree and find_path functions
		let rng = &mut thread_rng();
		let value = Fr::random(rng.clone());
		let leaves = vec![
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			value,
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
		];
		let mut merkle = MerkleTree::<Fr, Params>::build_tree(leaves, 4);

		let path = merkle.find_path(value);
		assert!(path.verify());
		// Assert last element of the vector and the root of the tree
		assert_eq!(
			path.path_vec[(2 * merkle.height)],
			merkle.nodes[&merkle.height][0]
		);
	}

	#[test]
	fn should_build_tree_from_small_vec() {
		// Testing build_tree and find_path functions with a small vector
		let rng = &mut thread_rng();
		let value = Fr::random(rng.clone());
		let mut merkle = MerkleTree::<Fr, Params>::build_tree(vec![value], 0);
		let path = merkle.find_path(value);
		assert!(path.verify());
		// Assert last element of the vector and the root of the tree
		assert_eq!(
			path.path_vec[(2 * merkle.height)],
			merkle.nodes[&merkle.height][0]
		);
	}
}
