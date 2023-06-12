use crate::{FieldExt, Hasher};
use num_integer::Integer;
use num_traits::pow;
use std::{collections::HashMap, marker::PhantomData};

const WIDTH: usize = 5;

#[derive(Clone, Debug)]
/// MerkleTree structure
pub struct MerkleTree<F: FieldExt, const ARITY: usize, const HEIGHT: usize, H>
where
	H: Hasher<F, WIDTH>,
{
	/// HashMap to keep the level and index of the nodes
	pub(crate) nodes: HashMap<usize, Vec<F>>,
	/// Height of the tree
	pub(crate) height: usize,
	/// Root of the tree
	pub(crate) root: F,
	/// PhantomData for the hasher
	_h: PhantomData<H>,
}

impl<F: FieldExt, const ARITY: usize, const HEIGHT: usize, H> MerkleTree<F, ARITY, HEIGHT, H>
where
	H: Hasher<F, WIDTH>,
{
	/// Build a MerkleTree from given leaf nodes and height
	pub fn build_tree(mut leaves: Vec<F>) -> Self {
		assert!(leaves.len() <= pow(ARITY, HEIGHT));
		assert!(ARITY <= WIDTH);

		// 0th level is the leaf level and the max level is the root level
		let mut nodes = HashMap::new();
		// Assign zero to the leaf values if they are empty
		for _i in leaves.len()..pow(ARITY, HEIGHT) {
			leaves.push(F::ZERO);
		}
		nodes.insert(0, leaves);

		let mut hasher_inputs = [F::ZERO; WIDTH];
		for level in 0..HEIGHT {
			let mut hashes = Vec::new();
			for i in 0..nodes[&level].len() {
				if i % ARITY != 0 {
					continue;
				}
				for j in 0..ARITY {
					hasher_inputs[j] = nodes[&level][i + j];
				}
				let hasher = H::new(hasher_inputs);
				hashes.push(hasher.finalize()[0]);
			}
			nodes.insert(level + 1, hashes);
		}
		let root = nodes[&HEIGHT][0].clone();
		MerkleTree { nodes, height: HEIGHT, root, _h: PhantomData }
	}
}

#[derive(Clone)]
/// Path structure
pub struct Path<F: FieldExt, const ARITY: usize, const HEIGHT: usize, const LENGTH: usize, H>
where
	H: Hasher<F, WIDTH>,
{
	/// Value that is based on for construction of the path
	pub(crate) value: F,
	/// Array that keeps the path
	pub(crate) path_arr: [[F; ARITY]; LENGTH],
	/// PhantomData for the hasher
	_h: PhantomData<H>,
}

impl<F: FieldExt, const ARITY: usize, const HEIGHT: usize, const LENGTH: usize, H>
	Path<F, ARITY, HEIGHT, LENGTH, H>
where
	H: Hasher<F, WIDTH>,
{
	/// Find path for the given value to the root
	pub fn find_path(
		merkle_tree: &MerkleTree<F, ARITY, HEIGHT, H>, mut value_index: usize,
	) -> Path<F, ARITY, HEIGHT, LENGTH, H> {
		let value = merkle_tree.nodes[&0][value_index];
		let mut path_arr: [[F; ARITY]; LENGTH] = [[F::ZERO; ARITY]; LENGTH];

		for level in 0..merkle_tree.height {
			let wrap = value_index.div_rem(&ARITY);
			for i in 0..ARITY {
				path_arr[level][i] = merkle_tree.nodes[&level][wrap.0 * ARITY + i];
			}
			value_index = value_index / ARITY;
		}

		path_arr[merkle_tree.height][0] = merkle_tree.root;
		Self { value, path_arr, _h: PhantomData }
	}

	/// Sanity check for the path array
	pub fn verify(&self) -> bool {
		let mut is_satisfied = true;
		let mut hasher_inputs = [F::ZERO; WIDTH];
		for i in 0..self.path_arr.len() - 1 {
			for j in 0..ARITY {
				hasher_inputs[j] = self.path_arr[i][j];
			}
			let hasher = H::new(hasher_inputs);
			is_satisfied = is_satisfied & self.path_arr[i + 1].contains(&(hasher.finalize()[0]));
		}
		is_satisfied
	}
}

#[cfg(test)]
mod test {
	use super::MerkleTree;
	use crate::{
		merkle_tree::native::Path, params::poseidon_bn254_5x5::Params, poseidon::native::Poseidon,
	};
	use halo2::{arithmetic::Field, halo2curves::bn256::Fr};
	use rand::thread_rng;

	#[test]
	fn should_build_tree_and_find_path_arity_2() {
		// Testing build_tree and find_path functions with arity 2
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
		];
		let merkle = MerkleTree::<Fr, 2, 3, Poseidon<Fr, 5, Params>>::build_tree(leaves);
		let path = Path::<Fr, 2, 3, 4, Poseidon<Fr, 5, Params>>::find_path(&merkle, 4);

		assert!(path.verify());
		// Assert last element of the array and the root of the tree
		assert_eq!(path.path_arr[merkle.height][0], merkle.root);
	}

	#[test]
	fn should_build_tree_and_find_path_arity_3() {
		// Testing build_tree and find_path functions with arity 3
		let rng = &mut thread_rng();
		let value = Fr::random(rng.clone());
		let leaves = vec![
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			value,
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
		];
		let merkle = MerkleTree::<Fr, 3, 3, Poseidon<Fr, 5, Params>>::build_tree(leaves);
		let path = Path::<Fr, 3, 3, 4, Poseidon<Fr, 5, Params>>::find_path(&merkle, 7);

		assert!(path.verify());
		// Assert last element of the array and the root of the tree
		assert_eq!(path.path_arr[merkle.height][0], merkle.root);
	}

	#[test]
	fn should_build_small_tree() {
		// Testing build_tree and find_path functions with a small array
		let rng = &mut thread_rng();
		let value = Fr::random(rng.clone());
		let merkle = MerkleTree::<Fr, 2, 0, Poseidon<Fr, 5, Params>>::build_tree(vec![value]);
		let path = Path::<Fr, 2, 0, 1, Poseidon<Fr, 5, Params>>::find_path(&merkle, 0);
		assert!(path.verify());
		// Assert last element of the array and the root of the tree
		assert_eq!(path.path_arr[merkle.height][0], merkle.root);
	}
}
