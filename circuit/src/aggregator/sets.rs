use super::{
	common_poly::{CommonPolynomial, CommonPolynomialEvaluation, Domain, Fraction},
	msm::MSM,
	protocol::{Expression, Protocol, Query, Rotation},
	shplonk::powers,
	transcript::Transcript,
};
use crate::{
	ecc::native::EcPoint,
	integer::{native::Integer, rns::RnsParams},
	params::RoundParams,
	poseidon::native::sponge::PoseidonSponge,
};
use halo2wrong::{
	curves::{group::ff::PrimeField, Coordinates, CurveAffine, FieldExt},
	halo2::{arithmetic::Field, plonk::Error},
};
use itertools::Itertools;
use std::{
	collections::{BTreeSet, HashMap},
	io::Read,
	iter,
	iter::Sum,
	marker::PhantomData,
};

use super::{NUM_BITS, NUM_LIMBS, WIDTH};

pub struct RotationsSet {
	rotations: Vec<Rotation>,
	polys: Vec<usize>,
}

pub fn rotations_sets(queries: &[Query]) -> Vec<RotationsSet> {
	let mut poly_rotations = Vec::<(usize, Vec<Rotation>)>::new();
	for query in queries {
		let pos_opt = poly_rotations.iter().position(|(poly, _)| *poly == query.poly);
		if let Some(pos) = pos_opt {
			let (_, rotations) = &mut poly_rotations[pos];
			if !rotations.contains(&query.rotation) {
				rotations.push(query.rotation);
			}
		} else {
			poly_rotations.push((query.poly, vec![query.rotation]));
		}
	}

	let mut sets = Vec::<RotationsSet>::new();
	for (poly, rotations) in poly_rotations {
		let pos_opt = sets.iter().position(|set| {
			BTreeSet::from_iter(set.rotations.iter()) == BTreeSet::from_iter(rotations.iter())
		});
		if let Some(pos) = pos_opt {
			let set = &mut sets[pos];
			if !set.polys.contains(&poly) {
				set.polys.push(poly);
			}
		} else {
			let set = RotationsSet { rotations, polys: vec![poly] };
			sets.push(set);
		}
	}
	sets
}

pub struct IntermediateSet<C: CurveAffine, R>
where
	R: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	pub(crate) rotations: Vec<Rotation>,
	pub(crate) polys: Vec<usize>,
	pub(crate) z_s: C::ScalarExt,
	pub(crate) evaluation_coeffs: Vec<Fraction<C::ScalarExt>>,
	pub(crate) commitment_coeff: Option<Fraction<C::ScalarExt>>,
	pub(crate) remainder_coeff: Option<Fraction<C::ScalarExt>>,
	_rns: PhantomData<R>,
}

impl<C: CurveAffine, R> IntermediateSet<C, R>
where
	R: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
{
	pub fn new(
		domain: &Domain<C::ScalarExt>, rotations: Vec<Rotation>, powers_of_z: &[C::ScalarExt],
		z_prime: &C::ScalarExt, z_prime_minus_z_omega_i: &HashMap<Rotation, C::ScalarExt>,
		z_s_1: &Option<C::ScalarExt>,
	) -> Self {
		let mut omegas = Vec::new();
		for rotation in &rotations {
			let omega = domain.rotate_scalar(C::Scalar::one(), *rotation);
			omegas.push(omega);
		}

		let normalized_ell_primes = omegas
			.iter()
			.enumerate()
			.map(|(j, omega_j)| {
				omegas
					.iter()
					.enumerate()
					.filter(|&(i, _)| i != j)
					.fold(C::Scalar::one(), |acc, (_, omega_i)| {
						acc * (*omega_j - omega_i)
					})
			})
			.collect_vec();

		let z = &powers_of_z[1].clone();
		let k_minus_one = rotations.len() - 1;
		let mut z_pow_k_minus_one = C::ScalarExt::one();
		for (i, pw_z) in powers_of_z.iter().enumerate().skip(1) {
			if k_minus_one & (1 << i) == 1 {
				z_pow_k_minus_one *= pw_z;
			}
		}

		let mut barycentric_weights = Vec::new();
		for (omega, norm_prime) in omegas.iter().zip(normalized_ell_primes.iter()) {
			let sum = sum_products_with_coeff_and_constant(
				&[
					(*norm_prime, z_pow_k_minus_one.clone(), z_prime.clone()),
					(-(*norm_prime * omega), z_pow_k_minus_one.clone(), z.clone()),
				],
				&C::ScalarExt::zero(),
			);
			let sum_fraction = Fraction::one_over(sum);
			barycentric_weights.push(sum_fraction);
		}

		let z_s = rotations
			.iter()
			.map(|rotation| z_prime_minus_z_omega_i.get(rotation).unwrap().clone())
			.reduce(|acc, z_prime_minus_z_omega_i| acc * z_prime_minus_z_omega_i)
			.unwrap();
		let z_s_1_over_z_s = z_s_1.clone().map(|z_s_1| Fraction::new(z_s_1, z_s.clone()));

		Self {
			rotations,
			polys: Vec::new(),
			z_s,
			evaluation_coeffs: barycentric_weights,
			commitment_coeff: z_s_1_over_z_s,
			remainder_coeff: None,
			_rns: PhantomData,
		}
	}

	pub fn msm(
		&self, commitments: &HashMap<usize, MSM<C, R>>, evaluations: &HashMap<Query, C::ScalarExt>,
		powers_of_mu: &[C::ScalarExt],
	) -> MSM<C, R> {
		let mut msm = MSM::default();
		for (poly, power_of_mu) in self.polys.iter().zip(powers_of_mu.iter()) {
			let mut commitment = self
				.commitment_coeff
				.as_ref()
				.map(|commitment_coeff| {
					let mut comm = commitments.get(poly).unwrap().clone();
					comm.scale(&commitment_coeff.evaluate());
					comm
				})
				.unwrap_or_else(|| commitments.get(poly).unwrap().clone());

			let reminder_coeff_eval = self.remainder_coeff.as_ref().unwrap().evaluate();

			let mut sum = C::ScalarExt::zero();
			for (rotation, coeff) in self.rotations.iter().zip(self.evaluation_coeffs.iter()) {
				let q = Query::new(*poly, *rotation);
				let res = coeff.evaluate() * evaluations.get(&q).unwrap();
				sum += res;
			}
			let remainder = reminder_coeff_eval * sum;
			msm += (commitment - MSM::scalar(remainder)) * power_of_mu;
		}
		msm
	}

	pub fn denoms(&mut self) -> impl IntoIterator<Item = &'_ mut C::ScalarExt> {
		if self.evaluation_coeffs.first().unwrap().denom().is_some() {
			self.evaluation_coeffs
				.iter_mut()
				.chain(self.commitment_coeff.as_mut())
				.filter_map(Fraction::denom_mut)
				.collect_vec()
		} else if self.remainder_coeff.is_none() {
			let barycentric_weights: Vec<C::ScalarExt> =
				self.evaluation_coeffs.iter().map(Fraction::evaluate).collect();
			let mut barycentric_weights_sum = C::ScalarExt::zero();
			for w in barycentric_weights {
				barycentric_weights_sum += w;
			}
			self.remainder_coeff = Some(match self.commitment_coeff.clone() {
				Some(coeff) => Fraction::new(coeff.evaluate(), barycentric_weights_sum),
				None => Fraction::one_over(barycentric_weights_sum),
			});
			vec![self.remainder_coeff.as_mut().unwrap().denom_mut().unwrap()]
		} else {
			unreachable!()
		}
	}
}

pub fn intermediate_sets<
	C: CurveAffine,
	PR: Protocol<C>,
	R: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
>(
	z: &C::ScalarExt, z_prime: &C::ScalarExt,
) -> Vec<IntermediateSet<C, R>> {
	let rotations_sets = rotations_sets(&PR::queries());

	let superset = rotations_sets.iter().flat_map(|set| set.rotations.clone()).sorted().dedup();

	let rotation_set_max = rotations_sets.iter().map(|set| set.rotations.len()).max().unwrap() - 1;
	let size = 2.max(rotation_set_max.next_power_of_two().ilog2() as usize + 1);

	let powers_of_z = powers(*z, size);

	let mut z_prime_minus_z_omega_i = HashMap::new();
	for rotation in superset {
		let omega = PR::domain().rotate_scalar(C::Scalar::one(), rotation);
		z_prime_minus_z_omega_i.insert(rotation, z_prime.clone() - z.clone() * omega);
	}

	let mut z_s_1: Option<C::ScalarExt> = None;
	let mut intermediate_sets = Vec::new();
	for set in rotations_sets {
		let intermetidate_set = IntermediateSet {
			polys: set.polys,
			..IntermediateSet::<C, R>::new(
				&PR::domain(),
				set.rotations,
				&powers_of_z,
				z_prime,
				&z_prime_minus_z_omega_i,
				&z_s_1,
			)
		};
		if z_s_1.is_none() {
			z_s_1 = Some(intermetidate_set.z_s.clone());
		};
		intermediate_sets.push(intermetidate_set);
	}
	intermediate_sets
}

fn sum_products_with_coeff_and_constant<F: FieldExt>(values: &[(F, F, F)], constant: &F) -> F {
	assert!(!values.is_empty());

	let combination =
		values.iter().map(|(coeff, lhs, rhs)| coeff.clone() * lhs.clone() * rhs.clone());
	iter::empty()
		.chain(if *constant == F::zero() { None } else { Some(*constant) })
		.chain(combination)
		.reduce(|acc, term| acc.clone() + term.clone())
		.unwrap()
}

pub fn batch_invert<'a, F: FieldExt>(values: impl IntoIterator<Item = &'a mut F>) {
	values
		.into_iter()
		.for_each(|value| *value = value.invert().unwrap_or_else(|| value.clone()))
}
