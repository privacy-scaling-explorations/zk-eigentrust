/// Native version of the chip
pub mod native;

use std::marker::PhantomData;

use crate::{
	gadgets::set::{FixedSetChip, FixedSetConfig},
	params::RoundParams,
	poseidon::{PoseidonChip, PoseidonConfig},
};
use halo2::{
	circuit::{AssignedCell, Layouter, Region},
	halo2curves::FieldExt,
	plonk::{Advice, Column, ConstraintSystem, Error},
};

const WIDTH: usize = 5;

/// Configuration elements for the circuit are defined here.
#[derive(Debug, Clone)]
pub struct MerklePathConfig {
	/// Configures an advice column for the temp.
	temp: Column<Advice>,
	/// Configures FixedSet circuit.
	set: FixedSetConfig,
	/// Configures Poseidon circuit.
	poseidon: PoseidonConfig<WIDTH>,
}

/// Constructs a chip for the circuit.
#[derive(Clone)]
pub struct MerklePathChip<F: FieldExt, const ARITY: usize, const LENGTH: usize, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Constructs cell arrays for the nodes.
	nodes: [[AssignedCell<F, F>; ARITY]; LENGTH],
	/// Constructs a phantom data for the parameters.
	_params: PhantomData<P>,
}

impl<F: FieldExt, const ARITY: usize, const LENGTH: usize, P> MerklePathChip<F, ARITY, LENGTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Create a new chip.
	pub fn new(nodes: [[AssignedCell<F, F>; ARITY]; LENGTH]) -> Self {
		MerklePathChip { nodes, _params: PhantomData }
	}

	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> MerklePathConfig {
		let temp = meta.advice_column();
		let set = FixedSetChip::<F, 2>::configure(meta);
		let poseidon = PoseidonChip::<_, WIDTH, P>::configure(meta);
		meta.enable_equality(temp);
		MerklePathConfig { temp, set, poseidon }
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self, config: MerklePathConfig, path_arr: [[F; ARITY]; LENGTH], zero: AssignedCell<F, F>,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		let mut root: Option<AssignedCell<F, F>> = None;
		for i in 0..path_arr.len() - 1 {
			let pos = PoseidonChip::<F, WIDTH, P>::new([
				self.nodes[i][0].clone(),
				self.nodes[i][1].clone(),
				zero.clone(),
				zero.clone(),
				zero.clone(),
			]);
			let hashes =
				pos.synthesize(&config.poseidon.clone(), layouter.namespace(|| "poseidon"))?;

			let set = FixedSetChip::<F, ARITY>::new(path_arr[i + 1], hashes[0].clone());
			let is_inside =
				set.synthesize(config.set.clone(), layouter.namespace(|| "is_inside_set"))?;

			// Enforce equality.
			// If value is not inside the set it will return 0 and will give an error.
			layouter.assign_region(
				|| "enforce_equality",
				|mut region: Region<'_, F>| {
					let is_inside_copied =
						is_inside_bool.copy_advice(|| "is_inside", &mut region, config.temp, 0)?;
					region.constrain_constant(is_inside_copied.cell(), F::one())?;
					Ok(())
				},
			)?;
			root = Some(hashes[0].clone());
		}

		Ok(root.unwrap())
	}
}

#[cfg(test)]
mod test {
	use std::usize;

	use super::*;
	use crate::{
		merkle_tree::native::{MerkleTree, Path},
		params::poseidon_bn254_5x5::Params,
		utils::{generate_params, prove_and_verify},
	};
	use halo2::{
		arithmetic::Field,
		circuit::{SimpleFloorPlanner, Value},
		dev::MockProver,
		halo2curves::bn256::{Bn256, Fr},
		plonk::{Circuit, Instance},
	};
	use rand::thread_rng;

	#[derive(Clone, Debug)]
	struct TestConfig {
		path: MerklePathConfig,
		temp: Column<Advice>,
		pub_ins: Column<Instance>,
	}

	#[derive(Clone)]
	struct TestCircuit<F: FieldExt, const ARITY: usize, const LENGTH: usize, P>
	where
		P: RoundParams<F, WIDTH>,
	{
		path_arr: [[F; ARITY]; LENGTH],
		_params: PhantomData<P>,
	}

	impl<F: FieldExt, const ARITY: usize, const LENGTH: usize, P> TestCircuit<F, ARITY, LENGTH, P>
	where
		P: RoundParams<F, WIDTH>,
	{
		fn new(path_arr: [[F; ARITY]; LENGTH]) -> Self {
			Self { path_arr, _params: PhantomData }
		}
	}

	impl<F: FieldExt, const ARITY: usize, const LENGTH: usize, P> Circuit<F>
		for TestCircuit<F, ARITY, LENGTH, P>
	where
		P: RoundParams<F, WIDTH>,
	{
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { path_arr: [[F::zero(); ARITY]; LENGTH], _params: PhantomData }
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
			let path = MerklePathChip::<_, ARITY, LENGTH, P>::configure(meta);
			let temp = meta.advice_column();
			let pub_ins = meta.instance_column();

			meta.enable_equality(temp);
			meta.enable_equality(pub_ins);

			TestConfig { path, temp, pub_ins }
		}

		fn synthesize(
			&self, config: TestConfig, mut layouter: impl Layouter<F>,
		) -> Result<(), Error> {
			let (path_vec, zero) = layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, F>| {
					let zero = region.assign_advice(
						|| "zero",
						config.temp,
						LENGTH * 2 + 1,
						|| Value::known(F::zero()),
					)?;
					let mut path_arr: [[Option<AssignedCell<F, F>>; ARITY]; LENGTH] =
						[[(); ARITY]; LENGTH].map(|_| [(); ARITY].map(|_| None));
					for i in 0..LENGTH {
						path_arr[i][0] = Some(region.assign_advice(
							|| "temp",
							config.temp,
							i,
							|| Value::known(self.path_arr[i][0]),
						)?);
						path_arr[i][1] = Some(region.assign_advice(
							|| "temp",
							config.temp,
							i + LENGTH,
							|| Value::known(self.path_arr[i][1]),
						)?);
					}
					Ok((path_arr.map(|a| a.map(|a| a.unwrap())), zero))
				},
			)?;
			let merkle_path = MerklePathChip::<F, ARITY, LENGTH, P>::new(path_vec);
			let root = merkle_path.synthesize(
				config.path,
				self.path_arr.clone(),
				zero,
				layouter.namespace(|| "merkle_path"),
			)?;
			layouter.constrain_instance(root.cell(), config.pub_ins, 0)?;

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
		let path = Path::<Fr, 2, 4, Params>::find_path(&merkle, value);
		let test_chip = TestCircuit::<Fr, 2, 4, Params>::new(path.path_arr);
		let k = 9;
		let pub_ins = vec![merkle.root];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_verify_path_big() {
		// Testing membership of the given path with a big tree and path.
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
		let path = Path::<Fr, 2, 9, Params>::find_path(&merkle, value);
		let test_chip = TestCircuit::<Fr, 2, 9, Params>::new(path.path_arr);
		let k = 10;
		let pub_ins = vec![merkle.root];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_verify_path_small() {
		// Testing membership of the given path with a small tree and path.
		let rng = &mut thread_rng();
		let value = Fr::random(rng.clone());
		let leaves = vec![Fr::random(rng.clone()), value];
		let merkle = MerkleTree::<Fr, Params>::build_tree(leaves, 1);
		let path = Path::<Fr, 2, 2, Params>::find_path(&merkle, value);
		let test_chip = TestCircuit::<Fr, 2, 2, Params>::new(path.path_arr);
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
		let path = Path::<Fr, 2, 5, Params>::find_path(&merkle, value);
		let test_chip = TestCircuit::<Fr, 2, 5, Params>::new(path.path_arr);
		let k = 9;
		let pub_ins = vec![merkle.root];
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, test_chip, &[&pub_ins], rng).unwrap();
		assert!(res);
	}
}
