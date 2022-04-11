use ark_std::collections::{BTreeMap, BTreeSet};

enum TreeError {
	RootNotFound,
	NodeNotFound,
	InvalidHeight,
}

enum Node {
	Internal(u64, u64),
	Leaf(u32),
}

struct KdTree {
	nodes: BTreeMap<u64, Node>,
	size: u32,
	height: u8,
}

impl KdTree {
	pub fn new(size: u32, height: u8, managers: Vec<u32>) -> Self {
		let mut nodes = BTreeMap::new();

		let mut next_level = BTreeSet::new();
		for (i, manager) in managers.iter().enumerate() {
			let iu64 = u64::from_le_bytes(i.to_le_bytes());
			let index = convert_index_to_last_level(iu64, height);
			nodes.insert(index, Node::Leaf(*manager));

			let parent = parent(index);
			next_level.insert(parent);
		}

		for level in 0..height {
			let mut new_level = BTreeSet::new();
			for index in next_level {
				let left = left_child(index);
				let right = right_child(index);
				nodes.insert(index, Node::Internal(left, right));

				let parent = parent(index);
				new_level.insert(parent);
			}
			next_level = new_level;
		}

		KdTree {
			nodes,
			size,
			height,
		}
	}

	pub fn search(&self, point: (u32, u32)) -> Result<u32, TreeError> {
		let mut node = self.nodes.get(&0).ok_or(TreeError::RootNotFound)?;
		let mut size = self.size;
		let mut i = 0;

		while let Node::Internal(left, right) = node {
			let is_x = i % 2 == 0;

			let next_size = size / 2;

			let node_index = if is_x {
				if point.0 < next_size {
					left
				} else {
					right
				}
			} else {
				if point.1 < next_size {
					left
				} else {
					right
				}
			};

			node = self.nodes.get(&node_index).ok_or(TreeError::NodeNotFound)?;
			size = next_size;
			i += 1;
		}

		match node {
			Node::Leaf(leaf) => Ok(*leaf),
			_ => Err(TreeError::NodeNotFound),
		}
	}
}

fn convert_index_to_last_level(index: u64, height: u8) -> u64 {
	index + (1 << height) - 1
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

/// Returns the index of the parent, given an index.
#[inline]
fn parent(index: u64) -> u64 {
	(index - 1) >> 1
}
