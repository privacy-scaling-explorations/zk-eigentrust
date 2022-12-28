use std::marker::PhantomData;

use halo2::halo2curves::FieldExt;
use num_traits::pow;
use std::collections::HashMap;

use crate::{params::RoundParams, poseidon::native::Poseidon};
const WIDTH: usize = 5;

#[derive(Clone, Debug)]
/// MerkleTree structure
pub struct MerkleTree<F: FieldExt, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// HashMap to keep the level and index of the nodes
	pub(crate) nodes: HashMap<usize, Vec<F>>,
	/// Height of the tree
	pub(crate) height: usize,
	/// Root of the tree
	pub(crate) root: F,
	/// PhantomData for the params
	_params: PhantomData<P>,
}

impl<F: FieldExt, P> MerkleTree<F, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Build a MerkleTree from given leaf nodes and height
	pub fn build_tree(mut leaves: Vec<F>, height: usize) -> Self {
		assert!(leaves.len() <= pow(2, height));
		// 0th level is the leaf level and the max level is the root level
		let mut nodes = HashMap::new();
		// Assign zero to the leaf values if they are empty
		for _i in leaves.len()..pow(2, height) {
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
		let root = nodes[&height][0].clone();
		MerkleTree { nodes, height, root, _params: PhantomData }
	}
}

#[derive(Clone)]
/// Path structure
pub struct Path<F: FieldExt, const ARITY: usize, const LENGTH: usize, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Value that is based on for construction of the path
	pub(crate) value: F,
	/// Array that keeps the path
	pub(crate) path_arr: [[F; ARITY]; LENGTH],
	/// PhantomData for the params
	_params: PhantomData<P>,
}

impl<F: FieldExt, const ARITY: usize, const LENGTH: usize, P> Path<F, ARITY, LENGTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Find path for the given value to the root
	pub fn find_path(merkle_tree: &MerkleTree<F, P>, value: F) -> Path<F, ARITY, LENGTH, P> {
		//
		// TODO: This way of finding index will fail if we have same inputs
		//
		let mut value_index = merkle_tree.nodes[&0].iter().position(|x| x == &value).unwrap();
		let mut path_arr: [[F; ARITY]; LENGTH] = [[F::zero(); ARITY]; LENGTH];
		// Childs for a parent node is 2n and 2n + 1.
		// value_index keeps index of that nodes in reverse order to apply this
		// algorithm.
		for level in 0..merkle_tree.height {
			if value_index % 2 == 1 {
				path_arr[level][0] = merkle_tree.nodes[&level][value_index - 1];
				path_arr[level][1] = merkle_tree.nodes[&level][value_index];
			} else {
				path_arr[level][0] = merkle_tree.nodes[&level][value_index];
				path_arr[level][1] = merkle_tree.nodes[&level][value_index + 1]
			}
			value_index = value_index / 2;
		}
		path_arr[merkle_tree.height][0] = merkle_tree.nodes[&merkle_tree.height][0];
		Self { value, path_arr, _params: PhantomData }
	}

	/// Sanity check for the path array
	pub fn verify(&self) -> bool {
		let mut is_satisfied = true;
		for i in 0..self.path_arr.len() - 1 {
			let pos_inputs =
				[self.path_arr[i][0], self.path_arr[i][1], F::zero(), F::zero(), F::zero()];
			let hasher: Poseidon<F, WIDTH, P> = Poseidon::new(pos_inputs);
			is_satisfied = is_satisfied | self.path_arr[i + 1].contains(&(hasher.permute()[0]));
		}
		is_satisfied
	}
}

#[cfg(test)]
mod test {
	use super::MerkleTree;
	use crate::{merkle_tree::native::Path, params::poseidon_bn254_5x5::Params};
	use halo2::{arithmetic::Field, halo2curves::bn256::Fr};
	use rand::thread_rng;

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
		let merkle = MerkleTree::<Fr, Params>::build_tree(leaves, 4);
		let path = Path::<Fr, 2, 5, Params>::find_path(&merkle, value);
		assert!(path.verify());
		// Assert last element of the vector and the root of the tree
		assert_eq!(path.path_arr[merkle.height][0], merkle.root);
	}

	#[test]
	fn should_build_tree_from_small_vec() {
		// Testing build_tree and find_path functions with a small vector
		let rng = &mut thread_rng();
		let value = Fr::random(rng.clone());
		let merkle = MerkleTree::<Fr, Params>::build_tree(vec![value], 0);
		let path = Path::<Fr, 2, 1, Params>::find_path(&merkle, value);
		assert!(path.verify());
		// Assert last element of the vector and the root of the tree
		assert_eq!(path.path_arr[merkle.height][0], merkle.root);
	}
}
