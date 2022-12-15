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
	first_leaf_index: usize,
}

impl<F: FieldExt, P> MerkleTree<F, P>
where
	P: RoundParams<F, WIDTH>,
{
	fn new(height: usize) -> Self {
		let mut first_leaf_index = 1;
		let mut nodes = 1;

		for i in 0..height {
			first_leaf_index *= 2;
			nodes = 2 * nodes;
		}
		first_leaf_index -= 1;
		nodes *= 2;
		let indexes = vec![None; nodes - 1];
		MerkleTree { _params: PhantomData, root: None, indexes, height, first_leaf_index }
	}

	fn implement_leaves(self: &mut MerkleTree<F, P>, values: Vec<F>) -> &Self {
		for i in 0..values.len() {
			self.indexes[self.first_leaf_index + i] = Some(values[i]);
		}
		self
	}

	fn build_tree(self: &mut MerkleTree<F, P>, height: usize) -> &Self {
		if height > 0 {
			let mut new_tree = MerkleTree::<F, P>::new(height - 1);
			let first_leaf_index = (new_tree.first_leaf_index * 2) + 1;
			let mut hash = Vec::new();
			for i in 0..first_leaf_index {
				let mut hasher: PoseidonSponge<F, WIDTH, P> = PoseidonSponge::new();
				if i % 2 == 0 {
					hasher.update(&[
						self.indexes[first_leaf_index + i].unwrap(),
						self.indexes[first_leaf_index + i + 1].unwrap(),
					]);
					hash.push(hasher.squeeze());
				}
			}
			new_tree.implement_leaves(hash.clone());
			for i in new_tree.first_leaf_index..new_tree.indexes.len() {
				self.indexes[i] = new_tree.indexes[i];
			}
			self.build_tree(new_tree.height);
		}
		self.root = self.indexes[0];
		self
	}

	fn find_path(self: &mut MerkleTree<F, P>, value: Option<F>, index: Option<usize>) -> Vec<F> {
		let mut is_inside = None;
		if value.is_some() {
			for i in (self.first_leaf_index - 1)..self.indexes.len() {
				if value == self.indexes[i] {
					is_inside = Some(i);
					break;
				}
			}
		} else {
			is_inside = Some((self.first_leaf_index - 1) + index.unwrap());
		}
		let mut path_vec: Vec<F> = Vec::new();
		let mut j = is_inside.unwrap();
		// Childs for a parent node is 2n and 2n - 1.
		// Reverse is (n / 2) and (n / 2 - 1).
		for i in 0..self.height {
			if j % 2 == 0 {
				path_vec.push(self.indexes[j - 1].unwrap());
				path_vec.push(self.indexes[j].unwrap());
				j = j / 2 - 1;
			} else {
				path_vec.push(self.indexes[j].unwrap());
				path_vec.push(self.indexes[j + 1].unwrap());
				j = j / 2;
			}
		}
		path_vec.push(self.root.unwrap());

		for i in 0..path_vec.len() - 2 {
			let mut hasher: PoseidonSponge<F, WIDTH, P> = PoseidonSponge::new();
			if i % 2 == 0 {
				hasher.update(&[path_vec[i], path_vec[i + 1]]);
				assert!(Self::is_inside(&path_vec, hasher.squeeze()));
			}
		}
		path_vec
	}

	fn is_inside(vector: &Vec<F>, value: F) -> bool {
		let mut answer = false;
		for i in 0..vector.len() {
			if value == vector[i] {
				answer = true;
			}
		}
		answer
	}
}

#[cfg(test)]
mod test {
	use crate::params::poseidon_bn254_5x5::Params;
	use halo2wrong::{curves::bn256::Fr, halo2::arithmetic::Field};
	use rand::thread_rng;

	use super::MerkleTree;

	#[test]
	fn should_build_tree() {
		let mut merkle = MerkleTree::<Fr, Params>::new(2);
		merkle
			.implement_leaves([(); 4].map(|_| <Fr as Field>::random(rand::thread_rng())).to_vec());

		merkle.build_tree(merkle.height);
		//println!("{:#?}", merkle.indexes);
	}

	#[test]
	fn should_find_path() {
		let rng = &mut thread_rng();
		let mut merkle = MerkleTree::<Fr, Params>::new(3);
		let value = Fr::random(rng.clone());
		merkle.implement_leaves(vec![
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			value,
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
		]);
		merkle.build_tree(merkle.height);
		let path = merkle.find_path(Some(value), None);
		assert_eq!(path[6], merkle.root.unwrap());
	}
}
