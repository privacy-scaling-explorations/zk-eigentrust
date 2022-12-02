use super::{
	common_poly::{CommonPolynomial, CommonPolynomialEvaluation},
	msm::MSM,
	protocol::{Expression, Protocol, Query, Rotation},
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
use std::{
	collections::{BTreeSet, HashMap},
	io::Read,
	iter,
	iter::Sum,
	marker::PhantomData,
};

use super::{NUM_BITS, NUM_LIMBS, WIDTH};

pub struct ShplonkProof<C: CurveAffine, P, PR, RNS>
where
	RNS: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
	PR: Protocol<C>,
	P: RoundParams<C::ScalarExt, 5>,
{
	instances: Vec<Vec<C::ScalarExt>>,
	auxiliaries: Vec<EcPoint<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, RNS>>,
	challenges: Vec<C::ScalarExt>,
	alpha: C::ScalarExt,
	quotients: Vec<EcPoint<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, RNS>>,
	z: C::ScalarExt,
	evaluations: Vec<C::ScalarExt>,
	mu: C::ScalarExt,
	gamma: C::ScalarExt,
	w: EcPoint<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, RNS>,
	z_prime: C::ScalarExt,
	w_prime: EcPoint<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, RNS>,
	_rounds_params: PhantomData<P>,
	_protocol: PhantomData<PR>,
}

impl<C: CurveAffine, P, PR, RNS> ShplonkProof<C, P, PR, RNS>
where
	RNS: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
	PR: Protocol<C>,
	P: RoundParams<C::ScalarExt, WIDTH>,
{
	fn read<I: Read>(
		instances: Vec<Vec<C::ScalarExt>>, transcript: &mut Transcript<C, I, P, RNS>,
	) -> Result<Self, Error> {
		let ins: Vec<usize> = instances.iter().map(|ins| ins.len()).collect();
		if PR::num_instance() != ins {
			return Err(Error::InvalidInstances);
		}

		for group in instances.iter() {
			for inst in group.iter() {
				transcript.common_scalar(inst.clone());
			}
		}

		let (auxiliaries, challenges) = {
			let (auxiliaries, challenges) = PR::num_witness()
				.iter()
				.zip(PR::num_challenge().iter())
				.map(|(&n, &m)| {
					Ok((
						transcript.read_n_points(n)?,
						transcript.squeeze_n_challenges(m),
					))
				})
				.collect::<Result<Vec<_>, Error>>()?
				.into_iter()
				.unzip::<_, _, Vec<_>, Vec<_>>();

			(
				auxiliaries.into_iter().flatten().collect(),
				challenges.into_iter().flatten().collect(),
			)
		};

		let alpha = transcript.squeeze_challenge();
		let max_degree = PR::relations().iter().map(Expression::degree).max().unwrap();
		let quotients = transcript.read_n_points(max_degree - 1)?;

		let z = transcript.squeeze_challenge();
		let evaluations = transcript.read_n_scalars(PR::evaluations().len())?;

		let mu = transcript.squeeze_challenge();
		let gamma = transcript.squeeze_challenge();
		let w = transcript.read_point()?;
		let z_prime = transcript.squeeze_challenge();
		let w_prime = transcript.read_point()?;

		Ok(Self {
			instances,
			auxiliaries,
			challenges,
			alpha,
			quotients,
			z,
			evaluations,
			mu,
			gamma,
			w,
			z_prime,
			w_prime,
			_rounds_params: PhantomData,
			_protocol: PhantomData,
		})
	}

	fn commitments(
		&self, common_poly_eval: &CommonPolynomialEvaluation<C::ScalarExt>,
	) -> HashMap<usize, MSM<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS, RNS>> {
		let prep = PR::preprocessed();
		let mut comms = Vec::new();
		for (i, value) in prep.iter().enumerate() {
			let coord_opt: Option<Coordinates<C>> = value.coordinates().into();
			let coord = coord_opt.unwrap();
			let x = coord.x();
			let y = coord.y();
			let int_x = Integer::from_w(x.clone());
			let int_y = Integer::from_w(y.clone());
			let ec_point = EcPoint::new(int_x, int_y);
			comms.push((i, MSM::base(ec_point)));
		}

		let auxiliary_offset = PR::preprocessed().len() + PR::num_instance().len();
		for (i, aux) in self.auxiliaries.iter().cloned().enumerate() {
			comms.push((auxiliary_offset + i, MSM::base(aux)));
		}

		let pws = powers(common_poly_eval.zn(), self.quotients.len());

		let mut sum = MSM::default();
		for (i, pw) in pws.iter().enumerate() {
			let mut quo_base = MSM::base(self.quotients[i].clone());
			quo_base.scale(pw);
			sum.extend(quo_base);
		}

		comms.push((PR::vanishing_poly(), sum));
		comms.into_iter().collect()
	}

	fn evaluations(
		&self, common_poly_eval: &CommonPolynomialEvaluation<C::ScalarExt>,
	) -> Result<HashMap<Query, C::ScalarExt>, Error> {
		let mut instance_evaluations = Vec::new();
		for insts in &self.instances {
			let mut sum = C::ScalarExt::zero();
			for (i, inst) in insts.iter().enumerate() {
				sum += *inst * common_poly_eval.get(CommonPolynomial::Lagrange(i as i32));
			}
			instance_evaluations.push(sum);
		}

		let mut evaluations: HashMap<Query, C::ScalarExt> = HashMap::new();
		for (i, evaluation) in instance_evaluations.iter().enumerate() {
			evaluations.insert(
				Query { poly: PR::preprocessed().len() + i, rotation: Rotation::cur() },
				*evaluation,
			);
		}
		for (i, eval) in self.evaluations.iter().enumerate() {
			evaluations.insert(PR::evaluations()[i].clone(), *eval);
		}

		let powers_of_alpha = powers(self.alpha, PR::relations().len());
		let mut quotient_evaluation = C::ScalarExt::zero();
		for (i, pw_alpha) in powers_of_alpha.iter().enumerate() {
			let relation = PR::relations();
			let eval_res = relation[i]
				.evaluate(
					&|scalar| Ok(scalar),
					&|poly| Ok(common_poly_eval.get(poly)),
					&|index| evaluations.get(&index).cloned().ok_or(Error::Synthesis),
					&|index| self.challenges.get(index).cloned().ok_or(Error::Synthesis),
					&|a| a.map(|a| -a),
					&|a, b| a.and_then(|a| Ok(a + b?)),
					&|a, b| a.and_then(|a| Ok(a * b?)),
					&|a, scalar| a.map(|a| a * scalar),
				)
				.map(|eval| powers_of_alpha[i] * eval)?;
			quotient_evaluation += eval_res;
		}
		quotient_evaluation = quotient_evaluation * &common_poly_eval.zn_minus_one_inv();

		evaluations.insert(
			Query { poly: PR::vanishing_poly(), rotation: Rotation::cur() },
			quotient_evaluation,
		);

		Ok(evaluations)
	}
}

fn powers<F: FieldExt>(scalar: F, n: usize) -> Vec<F> {
	iter::once(F::one())
		.chain(
			iter::successors(Some(scalar.clone()), |power| Some(power.clone() * scalar))
				.take(n - 1),
		)
		.collect()
}

pub fn langranges<C: CurveAffine, PR: Protocol<C>>(
	statements: &[Vec<C::ScalarExt>],
) -> impl IntoIterator<Item = i32> {
	let max_statement =
		statements.iter().map(|statement| statement.len()).max().unwrap_or_default() as i32;
	let relations_sum = PR::relations().into_iter().sum::<Expression<_>>();
	let used_langrange = relations_sum.used_langrange();
	used_langrange.into_iter().chain(0..max_statement)
}

struct RotationsSet {
	rotations: Vec<Rotation>,
	polys: Vec<usize>,
}

fn rotations_sets(queries: &[Query]) -> Vec<RotationsSet> {
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
