use super::rns::{compose_big, decompose_big, fe_to_big, RnsParams};
use halo2wrong::halo2::arithmetic::FieldExt;
use num_bigint::BigUint;
use std::marker::PhantomData;

/// Enum for the two different type of Quotient.
#[derive(Clone, Debug)]
pub enum Quotient<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Quotient type for the addition.
	Add(N),
	/// Quotient type for the multiplication.
	Mul(Integer<W, N, NUM_LIMBS, NUM_BITS, P>),
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	Quotient<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Returns Quotient type for the addition.
	pub fn add(self) -> Option<N> {
		match self {
			Quotient::Add(res) => Some(res),
			_ => None,
		}
	}

	/// Returns Quotient type for the multiplication.
	pub fn mul(self) -> Option<Integer<W, N, NUM_LIMBS, NUM_BITS, P>> {
		match self {
			Quotient::Mul(res) => Some(res),
			_ => None,
		}
	}
}

/// Structure for the ReductionWitness.
#[derive(Debug, Clone)]
pub struct ReductionWitness<
	W: FieldExt,
	N: FieldExt,
	const NUM_LIMBS: usize,
	const NUM_BITS: usize,
	P,
> where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Result from the operation.
	pub(crate) result: Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
	/// Quotient from the operation.
	pub(crate) quotient: Quotient<W, N, NUM_LIMBS, NUM_BITS, P>,
	/// Intermediate values from the operation.
	pub(crate) intermediate: [N; NUM_LIMBS],
	/// Residue values from the operation.
	pub(crate) residues: Vec<N>,
}

/// Structure for the Integer.
#[derive(Debug, Clone)]
pub struct Integer<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Integer limbs for the non-native operations.
	pub(crate) limbs: [N; NUM_LIMBS],
	/// Phantom data for the Wrong Field.
	_wrong_field: PhantomData<W>,
	/// Phantom data for the RnsParams.
	_rns: PhantomData<P>,
}

impl<W: FieldExt, N: FieldExt, const NUM_LIMBS: usize, const NUM_BITS: usize, P>
	Integer<W, N, NUM_LIMBS, NUM_BITS, P>
where
	P: RnsParams<W, N, NUM_LIMBS, NUM_BITS>,
{
	/// Creates a new object by decomposing given `limbs`.
	pub fn new(num: BigUint) -> Self {
		let limbs = decompose_big::<N, NUM_LIMBS, NUM_BITS>(num);
		Self::from_limbs(limbs)
	}

	/// Returns `limbs` from the object.
	pub fn from_limbs(limbs: [N; NUM_LIMBS]) -> Self {
		Self { limbs, _wrong_field: PhantomData, _rns: PhantomData }
	}

	/// Returns [`BigUint`] representation from the given `limbs`.
	pub fn value(&self) -> BigUint {
		let limb_values = self.limbs.map(|limb| fe_to_big(limb));
		compose_big::<NUM_LIMBS, NUM_BITS>(limb_values)
	}

	/// Non-native addition for given two [`Integer`].
	pub fn add(
		&self, other: &Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
	) -> ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P> {
		let p_prime = P::negative_wrong_modulus_decomposed();
		let a = self.value();
		let b = other.value();
		let (q, res) = P::construct_add_qr(a, b);

		// Calculate the intermediate values for the ReductionWitness.
		let mut t = [N::zero(); NUM_LIMBS];
		for i in 0..NUM_LIMBS {
			t[i] = self.limbs[i] + other.limbs[i] + p_prime[i] * q;
		}

		// Calculate the residue values for the ReductionWitness.
		let residues = P::residues(&res, &t);

		// Construct correct type for the ReductionWitness
		let result_int = Integer::from_limbs(res);
		let quotient_n = Quotient::Add(q);
		ReductionWitness { result: result_int, quotient: quotient_n, intermediate: t, residues }
	}

	/// Non-native multiplication for given two [`Integer`].
	pub fn mul(
		&self, other: &Integer<W, N, NUM_LIMBS, NUM_BITS, P>,
	) -> ReductionWitness<W, N, NUM_LIMBS, NUM_BITS, P> {
		let p_prime = P::negative_wrong_modulus_decomposed();
		let a = self.value();
		let b = other.value();
		let (q, res) = P::construct_mul_qr(a, b);

		// Calculate the intermediate values for the ReductionWitness.
		let mut t: [N; NUM_LIMBS] = [N::zero(); NUM_LIMBS];
		for k in 0..NUM_LIMBS {
			for i in 0..=k {
				let j = k - i;
				t[i + j] = t[i + j] + self.limbs[i] * other.limbs[j] + p_prime[i] * q[j];
			}
		}

		// Calculate the residue values for the ReductionWitness.
		let residues = P::residues(&res, &t);

		// Construct correct type for the ReductionWitness.
		let result_int = Integer::from_limbs(res);
		let quotient_int = Quotient::Mul(Integer::from_limbs(q));
		ReductionWitness { result: result_int, quotient: quotient_int, intermediate: t, residues }
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::wrong::rns::Bn256_4_68;
	use halo2wrong::curves::bn256::{Fq, Fr};
	use num_integer::Integer as NumInteger;
	use num_traits::{FromPrimitive, One, Zero};
	use std::str::FromStr;

	#[test]
	fn should_mul_two_numbers() {
		// Testing mul with two elements.
		let a_big = BigUint::from_str("2188824282428718582428782428718558718582").unwrap();
		let b_big = Bn256_4_68::wrong_modulus() - BigUint::from_u8(1).unwrap();
		let big_answer = a_big.clone() * b_big.clone();
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let b = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_big);
		let c = a.mul(&b);

		assert!(Bn256_4_68::constrain_binary_crt(
			c.intermediate, c.result.limbs, c.residues
		));
		assert_eq!(
			c.result.value(),
			big_answer.mod_floor(&Bn256_4_68::wrong_modulus())
		);
	}

	#[test]
	fn should_mul_zero() {
		// Testing mul with input zero.
		let a_big = BigUint::from_str("0").unwrap();
		let b_big = Bn256_4_68::wrong_modulus() - BigUint::from_u8(1).unwrap();
		let big_answer = a_big.clone() * b_big.clone();
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let b = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_big);
		let c = a.mul(&b);

		assert!(Bn256_4_68::constrain_binary_crt(
			c.intermediate, c.result.limbs, c.residues
		));
		assert_eq!(
			c.result.value(),
			big_answer.mod_floor(&Bn256_4_68::wrong_modulus())
		);
	}

	#[test]
	fn should_mul_accumulate_array_of_small_numbers() {
		// Testing mul with array of 8 small elements.
		let a_big = BigUint::from_str("2188824286654430").unwrap();
		let a_big_array = [
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
		];
		let carry = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(BigUint::one());
		let mut acc = carry.mul(&carry);
		let mut big_answer = BigUint::one();
		for i in 0..8 {
			big_answer *= a_big_array[i].clone();
			let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big_array[i].clone());
			acc = acc.result.mul(&a);

			assert!(Bn256_4_68::constrain_binary_crt(
				acc.intermediate, acc.result.limbs, acc.residues
			));
			assert_eq!(
				acc.result.value(),
				big_answer.mod_floor(&Bn256_4_68::wrong_modulus())
			);
		}
	}

	#[test]
	fn should_mul_accumulate_array_of_big_numbers() {
		// Testing mul with array of 8 big elements.
		let a_big = BigUint::from_str(
			"21888242871839275222246405745257275088696311157297823662689037894645226208582",
		)
		.unwrap();
		let a_big_array = [
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
		];
		let carry = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(BigUint::one());
		let mut acc = carry.mul(&carry);
		let mut big_answer = BigUint::one();
		for i in 0..8 {
			big_answer *= a_big_array[i].clone();
			let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big_array[i].clone());
			acc = acc.result.mul(&a);

			assert!(Bn256_4_68::constrain_binary_crt(
				acc.intermediate, acc.result.limbs, acc.residues
			));
			assert_eq!(
				acc.result.value(),
				big_answer.mod_floor(&Bn256_4_68::wrong_modulus())
			);
		}
	}

	#[test]
	fn should_add_two_numbers() {
		// Testing add with two elements.
		let a_big = BigUint::from_str(
			"2188824287183927522224640574525727508869631115729782366268903789426208582",
		)
		.unwrap();
		let b_big = BigUint::from_str(
			"21888242871839275222246405745257275088696311157297823662689037894645226208582",
		)
		.unwrap();
		let big_answer = a_big.clone() + b_big.clone();
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let b = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_big);
		let c = a.add(&b);

		assert!(Bn256_4_68::constrain_binary_crt(
			c.intermediate, c.result.limbs, c.residues
		));
		assert_eq!(
			c.result.value(),
			big_answer.mod_floor(&Bn256_4_68::wrong_modulus())
		);
	}

	#[test]
	fn should_add_biggest_number_plus() {
		// Testing add with biggest field value + 1.
		let a_big = BigUint::from_str("1").unwrap();
		let b_big = BigUint::from_str(
			"21888242871839275222246405745257275088696311157297823662689037894645226208582",
		)
		.unwrap();
		let big_answer = a_big.clone() + b_big.clone();
		let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big);
		let b = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(b_big);
		let c = a.add(&b);

		assert!(Bn256_4_68::constrain_binary_crt(
			c.intermediate, c.result.limbs, c.residues
		));
		assert_eq!(
			c.result.value(),
			big_answer.mod_floor(&Bn256_4_68::wrong_modulus())
		);
	}

	#[test]
	fn should_add_accumulate_array_of_small_numbers() {
		// Testing add with array of 8 small elements.
		let a_big = BigUint::from_str("4057452572750886963137894").unwrap();
		let a_big_array = [
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
		];
		let carry = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(BigUint::zero());
		let mut acc = carry.add(&carry);
		let mut big_answer = BigUint::zero();
		for i in 0..8 {
			big_answer += a_big_array[i].clone();
			let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big_array[i].clone());
			acc = acc.result.add(&a);

			assert!(Bn256_4_68::constrain_binary_crt(
				acc.intermediate, acc.result.limbs, acc.residues
			));
			assert_eq!(
				acc.result.value(),
				big_answer.mod_floor(&Bn256_4_68::wrong_modulus())
			);
		}
	}

	#[test]
	fn should_add_accumulate_array_of_big_numbers() {
		// Testing add with array of 8 big elements.
		let a_big = BigUint::from_str(
			"21888242871839275222246405745257275088696311157297823662689037894645226208582",
		)
		.unwrap();
		let a_big_array = [
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
			a_big.clone(),
		];
		let carry = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(BigUint::one());
		let mut acc = carry.mul(&carry);
		let mut big_answer = BigUint::one();
		for i in 0..8 {
			big_answer += a_big_array[i].clone();
			let a = Integer::<Fq, Fr, 4, 68, Bn256_4_68>::new(a_big_array[i].clone());
			acc = acc.result.add(&a);

			assert!(Bn256_4_68::constrain_binary_crt(
				acc.intermediate, acc.result.limbs, acc.residues
			));
			assert_eq!(
				acc.result.value(),
				big_answer.mod_floor(&Bn256_4_68::wrong_modulus())
			);
		}
	}
}
