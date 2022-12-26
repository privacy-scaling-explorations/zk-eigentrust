/// Native version of the chip
pub mod native;

use std::marker::PhantomData;

use crate::{
	gadgets::set::{FixedSetChip, FixedSetConfig},
	params::RoundParams,
	poseidon::{PoseidonChip, PoseidonConfig},
};
use halo2wrong::{
	curves::FieldExt,
	halo2::{
		circuit::{AssignedCell, Layouter, Region},
		plonk::{Advice, Column, ConstraintSystem, Error},
	},
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
pub struct MerklePathChip<F: FieldExt, const H: usize, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Constructs cell arrays for the nodes.
	nodes: [AssignedCell<F, F>; H],
	/// Constructs a phantom data for the parameters.
	_params: PhantomData<P>,
}

impl<F: FieldExt, const H: usize, P> MerklePathChip<F, H, P>
where
	P: RoundParams<F, WIDTH>,
{
	/// Create a new chip.
	pub fn new(nodes: [AssignedCell<F, F>; H]) -> Self {
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
		&self, config: MerklePathConfig, path_vec: Vec<F>, zero: AssignedCell<F, F>,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		let mut root: Option<AssignedCell<F, F>> = None;
		for i in 0..path_vec.len() - 1 {
			if i % 2 != 0 {
				continue;
			}
			let pos = PoseidonChip::<F, WIDTH, P>::new([
				self.nodes[i].clone(),
				self.nodes[i + 1].clone(),
				zero.clone(),
				zero.clone(),
				zero.clone(),
			]);
			let hashes =
				pos.synthesize(config.poseidon.clone(), layouter.namespace(|| "poseidon"))?;
			let mut is_inside: Option<FixedSetChip<F, 2>> = None;
			// When iteration reaches to the root's children this if will trigger and it
			// will check path_vec has the root inside the set or not. If yes it
			// will assign the root value and the function will return it.
			if i == path_vec.len() - 3 {
				is_inside = Some(FixedSetChip::<F, 2>::new(
					[path_vec[i + 2], F::zero()],
					hashes[0].clone(),
				));
				root = Some(hashes[0].clone());
			} else {
				is_inside = Some(FixedSetChip::<F, 2>::new(
					[path_vec[i + 2], path_vec[i + 3]],
					hashes[0].clone(),
				));
			}
			let is_inside_bool = is_inside
				.unwrap()
				.synthesize(config.set.clone(), layouter.namespace(|| "is_inside_set"))?;
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
		}

		Ok(root.unwrap())
	}
}

#[cfg(test)]
mod test {
	use std::usize;

	use super::*;
	use crate::{
		merkle_tree::native::MerkleTree,
		params::poseidon_bn254_5x5::Params,
		utils::{generate_params, prove_and_verify},
	};
	use halo2wrong::{
		curves::bn256::{Bn256, Fr},
		halo2::{
			arithmetic::Field,
			circuit::{SimpleFloorPlanner, Value},
			dev::MockProver,
			plonk::{Circuit, Instance},
		},
	};
	use rand::thread_rng;

	#[derive(Clone, Debug)]
	struct TestConfig {
		path: MerklePathConfig,
		temp: Column<Advice>,
		pub_ins: Column<Instance>,
	}

	#[derive(Clone)]
	struct TestCircuit<F: FieldExt, const H: usize, P>
	where
		P: RoundParams<F, WIDTH>,
	{
		path_vec: Vec<F>,
		_params: PhantomData<P>,
	}

	impl<F: FieldExt, const H: usize, P> TestCircuit<F, H, P>
	where
		P: RoundParams<F, WIDTH>,
	{
		fn new(path_vec: Vec<F>) -> Self {
			Self { path_vec, _params: PhantomData }
		}
	}

	impl<F: FieldExt, const H: usize, P> Circuit<F> for TestCircuit<F, H, P>
	where
		P: RoundParams<F, WIDTH>,
	{
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			Self { path_vec: vec![], _params: PhantomData }
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
			let path = MerklePathChip::<_, H, P>::configure(meta);
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
						H + 1,
						|| Value::known(F::zero()),
					)?;
					let mut path_vec: [Option<AssignedCell<F, F>>; H] = [(); H].map(|_| None);
					for i in 0..H {
						path_vec[i] = Some(region.assign_advice(
							|| "temp",
							config.temp,
							i,
							|| Value::known(self.path_vec[i]),
						)?);
					}
					Ok((path_vec.map(|a| a.unwrap()), zero))
				},
			)?;
			let merkle_path = MerklePathChip::<F, H, P>::new(path_vec);
			let root = merkle_path.synthesize(
				config.path,
				self.path_vec.clone(),
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
		let mut merkle = MerkleTree::<Fr, Params>::build_tree(leaves, 3);
		let path = merkle.find_path(value);
		let test_chip = TestCircuit::<Fr, 7, Params>::new(path.path_vec);
		let k = 9;
		let pub_ins = vec![merkle.nodes[&merkle.height][0]];
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
		let mut merkle = MerkleTree::<Fr, Params>::build_tree(leaves, 8);
		let path = merkle.find_path(value);
		let test_chip = TestCircuit::<Fr, 17, Params>::new(path.path_vec);
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
		let mut merkle = MerkleTree::<Fr, Params>::build_tree(leaves, 1);
		let path = merkle.find_path(value);
		let test_chip = TestCircuit::<Fr, 3, Params>::new(path.path_vec);
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
		let mut merkle = MerkleTree::<Fr, Params>::build_tree(leaves, 4);
		let path = merkle.find_path(value);
		let test_chip = TestCircuit::<Fr, 9, Params>::new(path.path_vec);
		let k = 9;
		let pub_ins = vec![merkle.root];
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, test_chip, &[&pub_ins], rng).unwrap();
		assert!(res);
	}
}
