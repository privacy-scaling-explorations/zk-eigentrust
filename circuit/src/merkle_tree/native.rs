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
	/// PhantomData for the params
	_params: PhantomData<P>,
	/// Variables with level and value to represent nodes
	nodes: HashMap<usize, Vec<F>>,
	/// Height of the tree
	height: usize,
}

impl<F: FieldExt, P> MerkleTree<F, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Create a new empty Merkle Tree with given height
	fn new(height: usize) -> Self {
		// 0th level is the leaf level and the max level is the root level
		let mut nodes = HashMap::new();
		for i in 0..height + 1 {
			let num_nodes = pow(2, height - i);
			let nodes_vec = vec![F::zero(); num_nodes];
			nodes.insert(i, nodes_vec);
		}
		MerkleTree { _params: PhantomData, nodes, height }
	}

	/// Put values to the given level of the tree
	fn put_values(&mut self, values: Vec<F>, level: usize) -> &Self {
		for i in 0..values.len() {
			self.nodes.get_mut(&level).unwrap()[i] = values[i];
		}
		self
	}

	/// Build tree's nodes and the root from given empty tree with only leaves
	fn build_tree(&mut self) -> &Self {
		for level in 0..self.height {
			let mut hash = Vec::new();
			for i in 0..self.nodes[&level].len() {
				if i % 2 == 0 {
					let hasher: Poseidon<F, WIDTH, P> = Poseidon::new([
						self.nodes[&level][i],
						self.nodes[&level][i + 1],
						F::zero(),
						F::zero(),
						F::zero(),
					]);
					hash.push(hasher.permute()[0]);
				}
			}
			self.put_values(hash, level + 1);
		}
		self
	}

	/// Find path for the given value to the root
	fn find_path(&mut self, value: F) -> Path<F, P> {
		let mut value_index = 0;
		for i in 0..self.nodes[&0].len() {
			if value == self.nodes[&0][i] {
				value_index = i;
				break;
			}
		}
		let mut path_vec: Vec<F> = Vec::new();
		let mut j = value_index;
		// Childs for a parent node is 2n and 2n + 1.
		// J keeps index of that nodes in reverse order to apply this algorithm.
		for level in 0..self.height {
			if j % 2 == 1 {
				path_vec.push(self.nodes[&level][j - 1]);
				path_vec.push(self.nodes[&level][j]);
			} else {
				path_vec.push(self.nodes[&level][j]);
				path_vec.push(self.nodes[&level][j + 1]);
			}
			j = j / 2;
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
	/// PhantomData for the params
	_params: PhantomData<P>,
	/// Value based on for the path
	value: F,
	/// Vector that keeps the path
	path_vec: Vec<F>,
}

impl<F: FieldExt, P> Path<F, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Sanity check for the path vector
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
				is_satisfied = is_satisfied | self.path_vec.contains(&(hasher.permute()[0]));
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
		// Testing build_tree and find_path functions
		let rng = &mut thread_rng();
		let mut merkle = MerkleTree::<Fr, Params>::new(4);
		let value = Fr::random(rng.clone());
		// Test the tree with 9 values while it can take 16
		merkle.put_values(
			vec![
				Fr::random(rng.clone()),
				Fr::random(rng.clone()),
				Fr::random(rng.clone()),
				Fr::random(rng.clone()),
				Fr::random(rng.clone()),
				Fr::random(rng.clone()),
				Fr::random(rng.clone()),
				Fr::random(rng.clone()),
				value,
			],
			0,
		);

		merkle.build_tree();
		let path = merkle.find_path(value);
		assert!(path.verify());
		// Assert last element of the array and the root of the tree
		assert_eq!(
			path.path_vec[(2 * merkle.height)],
			merkle.nodes[&merkle.height][0]
		);
	}
}
