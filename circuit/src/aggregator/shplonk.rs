use super::{
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
use std::{io::Read, marker::PhantomData};

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
		let quotients = {
			let max_degree = PR::relations().iter().map(Expression::degree).max().unwrap();
			transcript.read_n_points(max_degree - 1)?
		};

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
}
