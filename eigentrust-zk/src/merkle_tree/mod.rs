/// Native version of the chip
pub mod native;

use crate::{
	gadgets::set::{SetChipset, SetConfig},
	Chipset, CommonConfig, FieldExt, HasherChipset, RegionCtx,
};
use halo2::{
	circuit::{AssignedCell, Layouter, Region},
	plonk::Error,
};
use num_traits::pow;
use std::{collections::HashMap, marker::PhantomData};

const WIDTH: usize = 5;

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct MerkleConfig<F: FieldExt, H>
where
	H: HasherChipset<F, WIDTH>,
{
	hasher: H::Config,
}

impl<F: FieldExt, H> MerkleConfig<F, H>
where
	H: HasherChipset<F, WIDTH>,
{
	/// Construct a new config
	pub fn new(hasher: H::Config) -> Self {
		Self { hasher }
	}
}

/// Constructs a chip for the circuit.
#[derive(Clone)]
pub struct MerkleChip<F: FieldExt, const ARITY: usize, const HEIGHT: usize, H>
where
	H: HasherChipset<F, WIDTH>,
{
	/// Leaf nodes for the Merkle Tree.
	leaves: Vec<AssignedCell<F, F>>,
	/// Constructs a phantom data for the hasher.
	_hasher: PhantomData<H>,
}

impl<F: FieldExt, const ARITY: usize, const HEIGHT: usize, H> MerkleChip<F, ARITY, HEIGHT, H>
where
	H: HasherChipset<F, WIDTH>,
{
	/// Create a new chip.
	pub fn new(leaves: Vec<AssignedCell<F, F>>) -> Self {
		MerkleChip { leaves, _hasher: PhantomData }
	}
}

impl<F: FieldExt, const ARITY: usize, const HEIGHT: usize, H> Chipset<F>
	for MerkleChip<F, ARITY, HEIGHT, H>
where
	H: HasherChipset<F, WIDTH>,
{
	type Config = MerkleConfig<F, H>;
	type Output = AssignedCell<F, F>;

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		assert!(self.leaves.len() <= pow(ARITY, HEIGHT));
		assert!(ARITY <= WIDTH);

		let zero = layouter.assign_region(
			|| "assign_zero",
			|region: Region<'_, F>| {
				let mut ctx = RegionCtx::new(region, 0);
				ctx.assign_from_constant(common.advice[0], F::ZERO)
			},
		)?;

		// 0th level is the leaf level and the max level is the root level
		let mut nodes = HashMap::new();
		let mut leaves = self.leaves;
		// Assign zero to the leaf values if they are empty
		for _i in leaves.len()..pow(ARITY, HEIGHT) {
			leaves.push(zero.clone());
		}
		nodes.insert(0, leaves);

		for level in 0..HEIGHT {
			let mut hashes = Vec::new();
			let mut hasher_inputs = [(); WIDTH].map(|_| zero.clone());
			for i in 0..nodes[&level].len() {
				if i % ARITY != 0 {
					continue;
				}
				hasher_inputs[..ARITY].clone_from_slice(&nodes[&level][i..(ARITY + i)]);

				let hasher = H::new(hasher_inputs.clone());
				let hash =
					hasher.finalize(common, &config.hasher, layouter.namespace(|| "level_hash"))?;
				hashes.push(hash[0].clone());
			}
			nodes.insert(level + 1, hashes);
		}
		let root = nodes[&HEIGHT][0].clone();

		Ok(root)
	}
}

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct MerklePathConfig<F: FieldExt, H>
where
	H: HasherChipset<F, WIDTH>,
{
	hasher: H::Config,
	set: SetConfig,
}

impl<F: FieldExt, H> MerklePathConfig<F, H>
where
	H: HasherChipset<F, WIDTH>,
{
	/// Construct a new config given the selector of child chips
	pub fn new(hasher: H::Config, set: SetConfig) -> Self {
		Self { hasher, set }
	}
}

/// Constructs a chip for the circuit.
#[derive(Clone)]
pub struct MerklePathChip<F: FieldExt, const ARITY: usize, const LENGTH: usize, H>
where
	H: HasherChipset<F, WIDTH>,
{
	/// Constructs cell arrays for the nodes.
	nodes: [[AssignedCell<F, F>; ARITY]; LENGTH],
	/// Constructs a phantom data for the hasher.
	_hasher: PhantomData<H>,
}

impl<F: FieldExt, const ARITY: usize, const LENGTH: usize, H> MerklePathChip<F, ARITY, LENGTH, H>
where
	H: HasherChipset<F, WIDTH>,
{
	/// Create a new chip.
	pub fn new(nodes: [[AssignedCell<F, F>; ARITY]; LENGTH]) -> Self {
		MerklePathChip { nodes, _hasher: PhantomData }
	}
}

impl<F: FieldExt, const ARITY: usize, const LENGTH: usize, H> Chipset<F>
	for MerklePathChip<F, ARITY, LENGTH, H>
where
	H: HasherChipset<F, WIDTH>,
{
	type Config = MerklePathConfig<F, H>;
	type Output = AssignedCell<F, F>;

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		let zero = layouter.assign_region(
			|| "assign_zero",
			|region: Region<'_, F>| {
				let mut ctx = RegionCtx::new(region, 0);
				ctx.assign_from_constant(common.advice[0], F::ZERO)
			},
		)?;

		for i in 0..self.nodes.len() - 1 {
			let mut hasher_inputs = [(); WIDTH].map(|_| zero.clone());
			hasher_inputs[..ARITY].clone_from_slice(&self.nodes[i][..ARITY]);
			let hasher = H::new(hasher_inputs);
			let hashes =
				hasher.finalize(common, &config.hasher, layouter.namespace(|| "level_hash"))?;

			let set = SetChipset::<F>::new(self.nodes[i + 1].to_vec(), hashes[0].clone());
			let is_inside = set.synthesize(
				common,
				&config.set,
				layouter.namespace(|| "level_membership"),
			)?;

			// Enforce equality.
			// If value is not inside the set, it won't satisfy the constraint.
			layouter.assign_region(
				|| "enforce_equality",
				|region: Region<'_, F>| {
					let mut ctx = RegionCtx::new(region, 0);
					let is_inside_copied = ctx.copy_assign(common.advice[0], is_inside.clone())?;
					ctx.constrain_to_constant(is_inside_copied, F::ONE)?;
					Ok(())
				},
			)?;
		}

		// Root is expected at the index 0 on last level
		let root = self.nodes.last().unwrap()[0].clone();
		Ok(root)
	}
}

#[cfg(test)]
mod test {
	use std::usize;

	use super::*;
	use crate::{
		gadgets::{
			main::{MainChip, MainConfig},
			set::SetChip,
		},
		merkle_tree::native::{MerkleTree, Path},
		params::hasher::poseidon_bn254_5x5::Params,
		poseidon::{
			native::Poseidon, FullRoundChip, PartialRoundChip, PoseidonChipset, PoseidonConfig,
		},
		utils::{generate_params, prove_and_verify},
		Chip, CommonConfig,
	};
	use halo2::{
		arithmetic::Field,
		circuit::{SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::bn256::{Bn256, Fr},
		plonk::{Circuit, ConstraintSystem},
	};
	use itertools::Itertools;
	use rand::thread_rng;

	type NativeH = Poseidon<Fr, 5, Params>;
	type H = PoseidonChipset<Fr, 5, Params>;

	#[derive(Clone)]
	struct MerkleTestConfig {
		common: CommonConfig,
		merkle: MerkleConfig<Fr, H>,
	}

	#[derive(Clone)]
	struct MerkleTestCircuit<const ARITY: usize, const HEIGHT: usize> {
		leaves: Vec<Value<Fr>>,
		_h: PhantomData<H>,
	}

	impl<const ARITY: usize, const HEIGHT: usize> MerkleTestCircuit<ARITY, HEIGHT> {
		fn new(leaves: Vec<Fr>) -> Self {
			Self { leaves: leaves.iter().map(|x| Value::known(*x)).collect_vec(), _h: PhantomData }
		}
	}

	impl<const ARITY: usize, const HEIGHT: usize> Circuit<Fr> for MerkleTestCircuit<ARITY, HEIGHT> {
		type Config = MerkleTestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self {
				leaves: self.leaves.iter().map(|_| Value::unknown()).collect_vec(),
				_h: PhantomData,
			}
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> MerkleTestConfig {
			let common = CommonConfig::new(meta);
			let fr_selector = FullRoundChip::<_, WIDTH, Params>::configure(&common, meta);
			let pr_selector = PartialRoundChip::<_, WIDTH, Params>::configure(&common, meta);
			let poseidon = PoseidonConfig::new(fr_selector, pr_selector);
			let merkle = MerkleConfig::<Fr, H>::new(poseidon);

			MerkleTestConfig { common, merkle }
		}

		fn synthesize(
			&self, config: MerkleTestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let leaves = layouter.assign_region(
				|| "temp",
				|region: Region<'_, Fr>| {
					let mut ctx = RegionCtx::new(region, 0);
					let mut leaves = Vec::new();
					for i in 0..self.leaves.len() {
						let assigned =
							ctx.assign_advice(config.common.advice[0], self.leaves[i])?;
						leaves.push(assigned);
						ctx.next();
					}
					Ok(leaves)
				},
			)?;
			let merkle_tree = MerkleChip::<Fr, ARITY, HEIGHT, H>::new(leaves);
			let root = merkle_tree.synthesize(
				&config.common,
				&config.merkle,
				layouter.namespace(|| "merkle_tree"),
			)?;
			layouter.constrain_instance(root.cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	#[test]
	fn test_build_merkle_small() {
		// Testing merkle tree construction from the given tree leaves with arity 2.
		let rng = &mut thread_rng();
		let value = Fr::random(rng.clone());
		let leaves = vec![Fr::random(rng.clone()), Fr::random(rng.clone()), value];
		let merkle = MerkleTree::<Fr, 2, 2, NativeH>::build_tree(leaves.clone());
		let test_chip = MerkleTestCircuit::<2, 2>::new(leaves);
		let k = 8;
		let pub_ins = vec![merkle.root];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_build_merkle_big() {
		// Testing merkle tree construction from the given tree leaves with arity 2.
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
		let merkle = MerkleTree::<Fr, 2, 5, NativeH>::build_tree(leaves.clone());
		let test_chip = MerkleTestCircuit::<2, 5>::new(leaves);
		let k = 12;
		let pub_ins = vec![merkle.root];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_build_merkle_arity_3() {
		// Testing merkle tree construction from the given tree leaves with arity 3.
		let rng = &mut thread_rng();
		let value = Fr::random(rng.clone());
		let leaves = vec![Fr::random(rng.clone()), Fr::random(rng.clone()), value];
		let merkle = MerkleTree::<Fr, 3, 4, NativeH>::build_tree(leaves.clone());
		let test_chip = MerkleTestCircuit::<3, 4>::new(leaves);
		let k = 12;
		let pub_ins = vec![merkle.root];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_build_merkle_big_arity_4() {
		// Testing merkle tree construction from the given tree leaves with arity 4.
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
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
		];
		let merkle = MerkleTree::<Fr, 4, 2, NativeH>::build_tree(leaves.clone());
		let test_chip = MerkleTestCircuit::<4, 2>::new(leaves);
		let k = 12;
		let pub_ins = vec![merkle.root];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[derive(Clone)]
	struct PathTestConfig {
		common: CommonConfig,
		path: MerklePathConfig<Fr, H>,
	}

	#[derive(Clone)]
	struct PathTestCircuit<const ARITY: usize, const LENGTH: usize> {
		path_arr: [[Value<Fr>; ARITY]; LENGTH],
		_h: PhantomData<H>,
	}

	impl<const ARITY: usize, const LENGTH: usize> PathTestCircuit<ARITY, LENGTH> {
		fn new(path_arr: [[Fr; ARITY]; LENGTH]) -> Self {
			Self { path_arr: path_arr.map(|l| l.map(|x| Value::known(x))), _h: PhantomData }
		}
	}

	impl<const ARITY: usize, const LENGTH: usize> Circuit<Fr> for PathTestCircuit<ARITY, LENGTH> {
		type Config = PathTestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { path_arr: [[Value::unknown(); ARITY]; LENGTH], _h: PhantomData }
		}

		fn configure(meta: &mut ConstraintSystem<Fr>) -> PathTestConfig {
			let common = CommonConfig::new(meta);
			let main = MainConfig::new(MainChip::configure(&common, meta));
			let fr_selector = FullRoundChip::<_, WIDTH, Params>::configure(&common, meta);
			let pr_selector = PartialRoundChip::<_, WIDTH, Params>::configure(&common, meta);
			let poseidon = PoseidonConfig::new(fr_selector, pr_selector);
			let set_selector = SetChip::configure(&common, meta);
			let set = SetConfig::new(main, set_selector);
			let path = MerklePathConfig::<Fr, H>::new(poseidon, set);

			PathTestConfig { common, path }
		}

		fn synthesize(
			&self, config: PathTestConfig, mut layouter: impl Layouter<Fr>,
		) -> Result<(), Error> {
			let path_arr = layouter.assign_region(
				|| "temp",
				|region: Region<'_, Fr>| {
					let mut ctx = RegionCtx::new(region, 0);
					let mut path_arr: [[Option<AssignedCell<Fr, Fr>>; ARITY]; LENGTH] =
						[[(); ARITY]; LENGTH].map(|_| [(); ARITY].map(|_| None));

					for i in 0..LENGTH {
						for j in 0..ARITY {
							let assigned =
								ctx.assign_advice(config.common.advice[0], self.path_arr[i][j])?;
							path_arr[i][j] = Some(assigned);
							ctx.next();
						}
					}
					Ok(path_arr.map(|a| a.map(|a| a.unwrap())))
				},
			)?;
			let merkle_path = MerklePathChip::<Fr, ARITY, LENGTH, H>::new(path_arr);
			let root = merkle_path.synthesize(
				&config.common,
				&config.path,
				layouter.namespace(|| "merkle_path"),
			)?;
			layouter.constrain_instance(root.cell(), config.common.instance, 0)?;

			Ok(())
		}
	}

	#[test]
	fn test_verify_path() {
		// Testing membership of the given path.
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
		let merkle = MerkleTree::<Fr, 2, 3, NativeH>::build_tree(leaves);
		let path = Path::<Fr, 2, 3, 4, NativeH>::find_path(&merkle, 4);
		let test_chip = PathTestCircuit::<2, 4>::new(path.path_arr);
		let k = 9;
		let pub_ins = vec![merkle.root];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_verify_path_big() {
		// Testing membership of the given path with a big tree.
		let rng = &mut thread_rng();
		let value = Fr::random(rng.clone());
		let leaves = vec![
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			value,
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
		];
		let merkle = MerkleTree::<Fr, 2, 8, NativeH>::build_tree(leaves);
		let path = Path::<Fr, 2, 8, 9, NativeH>::find_path(&merkle, 3);
		let test_chip = PathTestCircuit::<2, 9>::new(path.path_arr);
		let k = 10;
		let pub_ins = vec![merkle.root];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_verify_path_small() {
		// Testing membership of the given path with a small tree.
		let rng = &mut thread_rng();
		let value = Fr::random(rng.clone());
		let leaves = vec![Fr::random(rng.clone()), value];
		let merkle = MerkleTree::<Fr, 2, 1, NativeH>::build_tree(leaves);
		let path = Path::<Fr, 2, 1, 2, NativeH>::find_path(&merkle, 1);
		let test_chip = PathTestCircuit::<2, 2>::new(path.path_arr);
		let k = 9;
		let pub_ins = vec![merkle.root];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_verify_path_big_arity_4() {
		// Testing membership of the given path with arity 4 and a big tree.
		let rng = &mut thread_rng();
		let value = Fr::random(rng.clone());
		let leaves = vec![
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			value,
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
			Fr::random(rng.clone()),
		];
		let merkle = MerkleTree::<Fr, 4, 4, NativeH>::build_tree(leaves);
		let path = Path::<Fr, 4, 4, 5, NativeH>::find_path(&merkle, 3);
		let test_chip = PathTestCircuit::<4, 5>::new(path.path_arr);
		let k = 9;
		let pub_ins = vec![merkle.root];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_verify_path_small_arity_5() {
		// Testing membership of the given path with arity 5 and a small tree.
		let rng = &mut thread_rng();
		let value = Fr::random(rng.clone());
		let leaves = vec![Fr::random(rng.clone()), value];
		let merkle = MerkleTree::<Fr, 5, 1, NativeH>::build_tree(leaves);
		let path = Path::<Fr, 5, 1, 2, NativeH>::find_path(&merkle, 1);
		let test_chip = PathTestCircuit::<5, 2>::new(path.path_arr);
		let k = 9;
		let pub_ins = vec![merkle.root];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_verify_path_production() {
		// Testing membership of the given path.
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
		let merkle = MerkleTree::<Fr, 2, 4, NativeH>::build_tree(leaves);
		let path = Path::<Fr, 2, 4, 5, NativeH>::find_path(&merkle, 4);
		let test_chip = PathTestCircuit::<2, 5>::new(path.path_arr);
		let k = 9;
		let pub_ins = vec![merkle.root];
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, test_chip, &[&pub_ins], rng).unwrap();
		assert!(res);
	}
}
