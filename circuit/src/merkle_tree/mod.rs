/// Native version of the chip
pub mod native;

use crate::{
	gadgets::set::{SetChipset, SetConfig},
	params::RoundParams,
	poseidon::{PoseidonChipset, PoseidonConfig},
	Chipset, CommonConfig, RegionCtx,
};
use halo2::{
	circuit::{AssignedCell, Layouter, Region},
	halo2curves::FieldExt,
	plonk::Error,
};
use std::marker::PhantomData;

const WIDTH: usize = 5;

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct MerklePathConfig {
	poseidon: PoseidonConfig,
	set: SetConfig,
}

impl MerklePathConfig {
	/// Construct a new config given the selector of child chips
	pub fn new(poseidon: PoseidonConfig, set: SetConfig) -> Self {
		Self { poseidon, set }
	}
}

/// Constructs a chip for the circuit.
#[derive(Clone)]
pub struct MerklePathChip<F: FieldExt, const LENGTH: usize, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Constructs cell arrays for the nodes.
	nodes: [[AssignedCell<F, F>; 2]; LENGTH],
	/// Constructs a phantom data for the parameters.
	_params: PhantomData<P>,
}

impl<F: FieldExt, const LENGTH: usize, P> MerklePathChip<F, LENGTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Create a new chip.
	pub fn new(nodes: [[AssignedCell<F, F>; 2]; LENGTH]) -> Self {
		MerklePathChip { nodes, _params: PhantomData }
	}
}

impl<F: FieldExt, const LENGTH: usize, P> Chipset<F> for MerklePathChip<F, LENGTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	type Config = MerklePathConfig;
	type Output = AssignedCell<F, F>;

	/// Synthesize the circuit.
	fn synthesize(
		self, common: &CommonConfig, config: &Self::Config, mut layouter: impl Layouter<F>,
	) -> Result<Self::Output, Error> {
		let zero = layouter.assign_region(
			|| "assign_zero",
			|region: Region<'_, F>| {
				let mut ctx = RegionCtx::new(region, 0);
				ctx.assign_from_constant(common.advice[0], F::zero())
			},
		)?;

		for i in 0..self.nodes.len() - 1 {
			let pos = PoseidonChipset::<F, WIDTH, P>::new([
				self.nodes[i][0].clone(),
				self.nodes[i][1].clone(),
				zero.clone(),
				zero.clone(),
				zero.clone(),
			]);
			let hashes = pos.synthesize(
				&common,
				&config.poseidon,
				layouter.namespace(|| "poseidon_level_hash"),
			)?;

			let set = SetChipset::<F>::new(self.nodes[i + 1].to_vec(), hashes[0].clone());
			let is_inside = set.synthesize(
				&common,
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
					ctx.constrain_to_constant(is_inside_copied, F::one())?;
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
			common::{MainChip, MainConfig},
			set::SetChip,
		},
		merkle_tree::native::{MerkleTree, Path},
		params::poseidon_bn254_5x5::Params,
		poseidon::{FullRoundChip, PartialRoundChip},
		utils::{generate_params, prove_and_verify},
		Chip, CommonChip, CommonConfig,
	};
	use halo2::{
		arithmetic::Field,
		circuit::{SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::bn256::{Bn256, Fr},
		plonk::{Circuit, ConstraintSystem},
	};
	use rand::thread_rng;

	#[derive(Clone, Debug)]
	struct TestConfig {
		common: CommonConfig,
		path: MerklePathConfig,
	}

	#[derive(Clone)]
	struct TestCircuit<F: FieldExt, const LENGTH: usize, P>
	where
		P: RoundParams<F, WIDTH>,
	{
		path_arr: [[F; 2]; LENGTH],
		_params: PhantomData<P>,
	}

	impl<F: FieldExt, const LENGTH: usize, P> TestCircuit<F, LENGTH, P>
	where
		P: RoundParams<F, WIDTH>,
	{
		fn new(path_arr: [[F; 2]; LENGTH]) -> Self {
			Self { path_arr, _params: PhantomData }
		}
	}

	impl<F: FieldExt, const LENGTH: usize, P> Circuit<F> for TestCircuit<F, LENGTH, P>
	where
		P: RoundParams<F, WIDTH>,
	{
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { path_arr: [[F::zero(); 2]; LENGTH], _params: PhantomData }
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
			let common = CommonChip::configure(meta);
			let fr_selector = FullRoundChip::<_, WIDTH, P>::configure(&common, meta);
			let pr_selector = PartialRoundChip::<_, WIDTH, P>::configure(&common, meta);
			let poseidon = PoseidonConfig::new(fr_selector, pr_selector);
			let set_selector = SetChip::configure(&common, meta);
			let main_selector = MainChip::configure(&common, meta);
			let main = MainConfig::new(main_selector);
			let set = SetConfig::new(set_selector, main);
			let path = MerklePathConfig::new(poseidon, set);

			TestConfig { common, path }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<F>,
		) -> Result<(), Error> {
			let path_arr = layouter.assign_region(
				|| "temp",
				|region: Region<'_, F>| {
					let mut ctx = RegionCtx::new(region, 0);

					let mut path_arr: [[Option<AssignedCell<F, F>>; 2]; LENGTH] =
						[[(); 2]; LENGTH].map(|_| [(); 2].map(|_| None));

					for i in 0..LENGTH {
						let l_val = Value::known(self.path_arr[i][0]);
						let r_val = Value::known(self.path_arr[i][1]);
						let l_assigned = ctx.assign_advice(config.common.advice[0], l_val)?;
						let r_assigned = ctx.assign_advice(config.common.advice[1], r_val)?;
						path_arr[i][0] = Some(l_assigned);
						path_arr[i][1] = Some(r_assigned);

						ctx.next();
					}
					Ok(path_arr.map(|a| a.map(|a| a.unwrap())))
				},
			)?;
			let merkle_path = MerklePathChip::<F, LENGTH, P>::new(path_arr);
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
		let merkle = MerkleTree::<Fr, Params>::build_tree(leaves, 3);
		let path = Path::<Fr, 4, Params>::find_path(&merkle, value);
		let test_chip = TestCircuit::<Fr, 4, Params>::new(path.path_arr);
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
		let merkle = MerkleTree::<Fr, Params>::build_tree(leaves, 8);
		let path = Path::<Fr, 9, Params>::find_path(&merkle, value);
		let test_chip = TestCircuit::<Fr, 9, Params>::new(path.path_arr);
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
		let merkle = MerkleTree::<Fr, Params>::build_tree(leaves, 1);
		let path = Path::<Fr, 2, Params>::find_path(&merkle, value);
		let test_chip = TestCircuit::<Fr, 2, Params>::new(path.path_arr);
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
		let merkle = MerkleTree::<Fr, Params>::build_tree(leaves, 4);
		let path = Path::<Fr, 5, Params>::find_path(&merkle, value);
		let test_chip = TestCircuit::<Fr, 5, Params>::new(path.path_arr);
		let k = 9;
		let pub_ins = vec![merkle.root];
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, test_chip, &[&pub_ins], rng).unwrap();
		assert!(res);
	}
}
