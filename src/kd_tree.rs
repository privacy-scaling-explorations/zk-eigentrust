use ark_std::{collections::BTreeMap, log2, vec::Vec};
use rand::Rng;
use tiny_keccak::{Hasher, Keccak};

/// Tree specific error variants
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeError {
	/// The Key is not found in the tree
	KeyNotFound,
	/// The number of leaves has to be a power of 2
	InvalidNumberOfLeaves,
}

/// Key used for identifying a leaf value outside the tree
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Default)]
pub struct Key([u8; 32]);

impl Key {
	/// Create a new Key from a slice of bytes
	pub fn new(key: [u8; 32]) -> Self {
		Key(key)
	}

	/// Create a new random Key
	pub fn rand<R: Rng>(rng: &mut R) -> Self {
		let mut key = [0u8; 32];
		rng.fill_bytes(&mut key);
		Key(key)
	}

	/// Hash the key with the keccak256 hash function
	pub fn hash(&self) -> Key {
		let mut hasher = Keccak::v256();
		hasher.update(&self.to_be_bytes());
		let mut hash = [0u8; 32];
		hasher.finalize(&mut hash);
		Key(hash)
	}

	/// Get the inner value of the Key
	pub fn to_be_bytes(&self) -> [u8; 32] {
		self.0
	}
}

/// For creating a Key from 2 parts
impl From<(u128, u128)> for Key {
	fn from(value: (u128, u128)) -> Self {
		let mut key = [0u8; 32];
		let first_part = value.0.to_be_bytes();
		let second_part = value.1.to_be_bytes();
		key[0..16].copy_from_slice(&first_part[..]);
		key[16..32].copy_from_slice(&second_part[..]);
		Key(key)
	}
}

impl From<usize> for Key {
	fn from(value: usize) -> Self {
		let mut key = [0u8; 32];
		let u_bytes = value.to_be_bytes();
		// On some targets, the usize is 4 bytes, and on some, it's 8 bytes
		// So, we need to copy the bytes manually
		for i in 0..u_bytes.len() {
			key[i] = u_bytes[i];
		}
		Key(key)
	}
}

/// An implementation of K-D Tree with fixed size and number of leaf nodes
///
/// It takes a vector of keys and maps them into a 2-dimensional plane.
/// Each key gets the same amount of territory in the plane,
/// which means the vector length has to be a power of 2.
/// Their position is based on the index inside the vector, e.g.:
/// If we had a vector of length 4, [manager1, manager2, manager3, manager4],
/// The first manager would be at the top left corner of the plane, like so:
//                x
// 10 ┌───────────┬───────────┐
//    │           │           │
//    │           │           │
//    │ manager1  │ manager2  │
//    │           │           │
//  5 ├───────────┼───────────┤ y
//    │           │           │
//    │           │           │
//    │ manager3  │ manager4  │
//    │           │           │
//    └───────────┴───────────┘
//    0           5          10
///
/// The tree of 4 leaves is structured as follows:
/// The root has an index of 0, and each child's index is a continuation of the
/// parent index The bottom-most level (the leaf level), starts with the index
/// of 0.
///
/// level 2:                  0         
/// level 1:            1           2   
/// level 0:         3     4     5     6
/// leaf level:      0     1     2     3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdTree {
	leaf_nodes: BTreeMap<u64, Key>,
}

impl KdTree {
	/// Creates a new KdTree with the given number of leaf nodes
	pub fn new(leaf_nodes: Vec<Key>) -> Result<Self, TreeError> {
		// It has to be a power of 2 so that every manager covers the equal amount of
		// space
		if !leaf_nodes.len().is_power_of_two() {
			return Err(TreeError::InvalidNumberOfLeaves);
		}
		// Converting the vector to a BTreeMap, to keep the indices as u64
		let map: BTreeMap<u64, Key> = leaf_nodes
			.iter()
			.enumerate()
			.map(|(i, key)| {
				let u_bytes = i.to_be_bytes();
				let mut u64_bytes = [0u8; 8];
				// On some targets, the usize is 4 bytes, and on some its 8 bytes
				// So, we need to copy the bytes manually
				for i in 0..u_bytes.len() {
					u64_bytes[i] = u_bytes[i];
				}
				let i_u64 = u64::from_be_bytes(u64_bytes);
				(i_u64, *key)
			})
			.collect();
		Ok(KdTree { leaf_nodes: map })
	}

	/// Searches the tree to find the leaf that has the closest distance to the
	/// given leaf
	pub fn search(&self, point: Key) -> Result<Key, TreeError> {
		// Take the first part of the key.
		let mut first_part = [0u8; 16];
		first_part.copy_from_slice(&point.0[0..16]);
		// Take the second part of the key.
		let mut second_part = [0u8; 16];
		second_part.copy_from_slice(&point.0[16..32]);

		// Using the first half of the key as the x coordinate, and the second half as
		// the y coordinate.
		let x = u128::from_be_bytes(first_part);
		let y = u128::from_be_bytes(second_part);

		// The size of the space is 2^128 x 2^128
		let mut size = u128::MAX;
		// We are starting at index 0.
		let mut index = 0;
		// Height is the log of the leaf nodes length.
		let height = u64::from(log2(self.leaf_nodes.len()));

		for i in 0..height {
			let (left, right) = children(index);
			let is_x = i % 2 == 0;

			let next_size = size / 2;

			let node_index = match (is_x, x < next_size, y < next_size) {
				// We are looking at the x axis
				(true, true, _) => left,
				(true, false, _) => right,
				// We are looking at the y axis
				(false, _, true) => left,
				(false, _, false) => right,
			};

			index = node_index;
			size = next_size;
		}

		let leaf_index = index - last_level(height);

		self.leaf_nodes
			.get(&leaf_index)
			.cloned()
			.ok_or(TreeError::KeyNotFound)
	}

	/// Returns the number of leaf nodes in the tree
	pub fn size(&self) -> usize {
		self.leaf_nodes.len()
	}
}

/// Get the starting index of the last level
#[inline]
fn last_level(height: u64) -> u64 {
	(1 << height) - 1
}

/// Returns the index of the left child, given an index.
#[inline]
fn left_child(index: u64) -> u64 {
	2 * index + 1
}

/// Returns the index of the right child, given an index.
#[inline]
fn right_child(index: u64) -> u64 {
	2 * index + 2
}

#[inline]
fn children(index: u64) -> (u64, u64) {
	(left_child(index), right_child(index))
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn invalid_number_of_leaves() {
		let leaf_nodes1 = vec![Key::new([0u8; 32]); 3];
		let leaf_nodes2 = vec![Key::new([0u8; 32]); 2];
		let res1 = KdTree::new(leaf_nodes1);
		let res2 = KdTree::new(leaf_nodes2);
		assert_eq!(res1.unwrap_err(), TreeError::InvalidNumberOfLeaves);
		assert!(res2.is_ok());
	}

	#[test]
	fn should_create() {
		let peer1 = Key::from((0, 0));
		let peer2 = Key::from((0, u128::MAX));
		let peer3 = Key::from((u128::MAX, 0));
		let peer4 = Key::from((u128::MAX, u128::MAX));

		let rng = &mut rand::thread_rng();
		let manager1 = Key::rand(rng);
		let manager2 = Key::rand(rng);
		let manager3 = Key::rand(rng);
		let manager4 = Key::rand(rng);

		let leaf_nodes = vec![manager1, manager2, manager3, manager4];

		let tree = KdTree::new(leaf_nodes).unwrap();

		let res1 = tree.search(peer1).unwrap();
		let res2 = tree.search(peer2).unwrap();
		let res3 = tree.search(peer3).unwrap();
		let res4 = tree.search(peer4).unwrap();

		assert_eq!(res1, manager1);
		assert_eq!(res2, manager2);
		assert_eq!(res3, manager3);
		assert_eq!(res4, manager4);
	}
}
