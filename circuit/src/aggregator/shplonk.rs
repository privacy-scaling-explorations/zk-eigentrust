use super::{
	accumulation::Accumulator,
	common_poly::{CommonPolynomial, CommonPolynomialEvaluation},
	msm::MSM,
	protocol::{Expression, Protocol, Query, Rotation},
	sets::{batch_invert, intermediate_sets, rotations_sets, IntermediateSet, RotationsSet},
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
	fn accumulate(
		&self, old_accumulator: Option<Accumulator<C, RNS>>,
	) -> Result<Accumulator<C, RNS>, Error> {
		let mut common_poly_eval = CommonPolynomialEvaluation::new(
			&PR::domain(),
			langranges::<C, PR>(&self.instances),
			self.z,
		);
		let mut sets = intermediate_sets::<C, PR, RNS>(&self.z, &self.z_prime);

		batch_invert(
			iter::empty()
				.chain(common_poly_eval.denoms())
				.chain(sets.iter_mut().flat_map(IntermediateSet::denoms)),
		);
		batch_invert(sets.iter_mut().flat_map(IntermediateSet::denoms));

		let commitments = self.commitments(&common_poly_eval);
		let evaluations = self.evaluations(&common_poly_eval)?;

		let set_max = sets.iter().map(|set| set.polys.len()).max().unwrap();
		let powers_of_mu = powers(self.mu, set_max);
		let msms = sets.iter().map(|set| set.msm(&commitments, &evaluations, &powers_of_mu));

		let gamma_powers = powers(self.gamma, sets.len());
		let f = msms
			.zip(gamma_powers.into_iter())
			.map(|(msm, power_of_gamma)| msm * &power_of_gamma)
			.sum::<MSM<C, RNS>>()
			- MSM::base(self.w.clone()) * &sets[0].z_s;

		let rhs = MSM::base(self.w_prime.clone());
		let lhs = f + rhs.clone() * &self.z_prime;

		let mut accumulator = Accumulator::new(lhs, rhs);
		if let Some(old_accumulator) = old_accumulator {
			accumulator.extend(old_accumulator);
		}

		Ok(accumulator)
	}

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
	) -> HashMap<usize, MSM<C, RNS>> {
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
			let mut i = 0;
			for inst in insts.iter() {
				sum += *inst * common_poly_eval.get(CommonPolynomial::Lagrange(i));
				i += 1;
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

pub fn powers<F: FieldExt>(scalar: F, n: usize) -> Vec<F> {
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
		statements.iter().map(|statement| statement.len()).max().unwrap_or_default();
	let relations_sum = PR::relations().into_iter().sum::<Expression<_>>();
	let used_langrange = relations_sum.used_langrange();
	let max_st_i32 = max_statement.try_into().unwrap();
	used_langrange.into_iter().chain(0..max_st_i32)
}
