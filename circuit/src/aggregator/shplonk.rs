use super::{
	common_poly::CommonPolynomialEvaluation,
	msm::MSM,
	protocol::{Expression, Protocol},
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
	halo2::plonk::Error,
};
use std::{collections::HashMap, io::Read, iter, marker::PhantomData};

use super::{NUM_BITS, NUM_LIMBS, WIDTH};

pub struct ShplonkProof<C: CurveAffine, P, PR, RNS>
where
	RNS: RnsParams<C::Base, C::ScalarExt, NUM_LIMBS, NUM_BITS>,
	PR: Protocol<C::ScalarExt, C>,
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
	PR: Protocol<C::ScalarExt, C>,
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
}

fn powers<F: FieldExt>(scalar: F, n: usize) -> Vec<F> {
	iter::once(F::one())
		.chain(
			iter::successors(Some(scalar.clone()), |power| Some(power.clone() * scalar))
				.take(n - 1),
		)
		.collect()
}
