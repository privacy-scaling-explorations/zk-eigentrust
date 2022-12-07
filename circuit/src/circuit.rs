use crate::{CommonConfig, PoseidonConfig};
use halo2wrong::{
	curves::FieldExt,
	halo2::plonk::{Advice, Column, Instance},
};
use std::marker::PhantomData;

const NUM_ITER: usize = 20;
const NUM_NEIGHBOURS: usize = 5;
const INITIAL_SCORE: f32 = 1000.;

/// The columns config for the main circuit.
#[derive(Clone, Debug)]
pub struct EigenTrustConfig {
	common: CommonConfig,
	poseidon: PoseidonConfig<5>,
	temp: Column<Advice>,
	pub_ins: Column<Instance>,
}

struct EigenTrust<F: FieldExt> {
	_f: PhantomData<F>,
}

#[cfg(test)]
mod test {
	use super::*;

	fn native(ops: [[f32; NUM_NEIGHBOURS]; NUM_NEIGHBOURS]) {
		let mut s: [f32; NUM_NEIGHBOURS] = [INITIAL_SCORE; NUM_NEIGHBOURS];

		for _ in 0..NUM_ITER {
			let mut distributions: [[f32; NUM_NEIGHBOURS]; NUM_NEIGHBOURS] =
				[[0.; NUM_NEIGHBOURS]; NUM_NEIGHBOURS];
			for j in 0..NUM_NEIGHBOURS {
				distributions[j] = ops[j].map(|v| v * s[j]);
			}

			let mut new_s: [f32; NUM_NEIGHBOURS] = [0.; NUM_NEIGHBOURS];
			for i in 0..NUM_NEIGHBOURS {
				for j in 0..NUM_NEIGHBOURS {
					new_s[i] += distributions[j][i];
				}
			}

			s = new_s;

			println!("[{}]", s.map(|v| format!("{:>9.4}", v)).join(", "));
		}
	}

	#[test]
	fn test_closed_graph_native() {
		let ops = [
			[0.0, 0.2, 0.3, 0.5, 0.0],
			[0.1, 0.0, 0.1, 0.1, 0.7],
			[0.4, 0.1, 0.0, 0.2, 0.3],
			[0.1, 0.1, 0.7, 0.0, 0.1],
			[0.3, 0.1, 0.4, 0.2, 0.0],
		];
		native(ops);
	}
}
