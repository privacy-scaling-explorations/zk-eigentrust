use super::transcript::PoseidonRead;
use halo2::{
	arithmetic::{compute_inner_product, Field, FieldExt},
	halo2curves::{pairing::Engine, serde::SerdeObject, CurveAffine},
	plonk::{
		vanishing, ChallengeBeta, ChallengeGamma, ChallengeTheta, ChallengeX, ChallengeY, Error,
		VerifyingKey,
	},
	poly::{
		commitment::{Params, MSM},
		kzg::{commitment::ParamsKZG, msm::MSMKZG},
		query::{CommitmentReference, Query, VerifierQuery},
	},
	transcript::{read_n_scalars, Transcript, TranscriptRead},
};
use std::fmt::Debug;

/// CommitmentData
#[derive(Debug)]
pub struct CommitmentData<E: Engine + Debug> {
	/// queries
	pub queries: Vec<VerifierQueryOwned<E::G1Affine, MSMKZG<E>>>,
	/// point
	pub point: E::Scalar,
}

/// construct_intermediate_sets
pub fn construct_intermediate_sets<E: Engine + Debug>(
	queries: Vec<VerifierQueryOwned<E::G1Affine, MSMKZG<E>>>,
) -> Vec<CommitmentData<E>> {
	let mut point_query_map: Vec<(E::Scalar, Vec<VerifierQueryOwned<E::G1Affine, MSMKZG<E>>>)> =
		Vec::new();
	for query in queries {
		if let Some(pos) = point_query_map.iter().position(|(point, _)| *point == query.get_point())
		{
			let (_, queries) = &mut point_query_map[pos];
			queries.push(query);
		} else {
			point_query_map.push((query.get_point(), vec![query]));
		}
	}

	point_query_map
		.into_iter()
		.map(|(point, queries)| CommitmentData { queries, point })
		.collect()
}

#[derive(Clone, Debug)]
/// CommitmentReference
pub enum CommitmentReferenceOwned<C: CurveAffine, M: MSM<C>> {
	/// Commitment
	Commitment(C),
	/// MSM
	MSM(M),
}

#[derive(Debug, Clone)]
/// A polynomial query at a point
pub struct VerifierQueryOwned<C: CurveAffine, M: MSM<C>> {
	/// point at which polynomial is queried
	pub point: C::Scalar,
	/// commitment to polynomial
	pub commitment: CommitmentReferenceOwned<C, M>,
	/// evaluation of polynomial at query point
	pub eval: C::Scalar,
}

impl<C: CurveAffine, M: MSM<C>> VerifierQueryOwned<C, M> {
	/// get_point
	pub fn get_point(&self) -> C::Scalar {
		self.point
	}

	/// get_point
	pub fn get_commitment(&self) -> CommitmentReferenceOwned<C, M> {
		self.commitment.clone()
	}

	/// get_eval
	pub fn get_eval(&self) -> C::Scalar {
		self.eval
	}
}

/// Returns a boolean indicating whether or not the proof is valid
pub fn setup_verify_queries<E: Engine + Debug>(
	params: ParamsKZG<E>, vk: VerifyingKey<E::G1Affine>, instances: &[&[&[E::Scalar]]],
	transcript: &mut PoseidonRead<E::G1Affine>,
) -> Result<Vec<VerifierQueryOwned<E::G1Affine, MSMKZG<E>>>, Error>
where
	E::G1Affine: SerdeObject,
	E::G2Affine: SerdeObject,
{
	// Check that instances matches the expected number of instance columns
	for instances in instances.iter() {
		if instances.len() != vk.cs().num_instance_columns() {
			return Err(Error::InvalidInstances);
		}
	}

	let num_proofs = instances.len();

	// Hash verification key into transcript
	vk.hash_into(transcript)?;

	for instance in instances.iter() {
		for instance in instance.iter() {
			for value in instance.iter() {
				transcript.common_scalar(*value)?;
			}
		}
	}

	// Hash the prover's advice commitments into the transcript and squeeze
	// challenges
	let (advice_commitments, challenges) = {
		let mut advice_commitments =
			vec![vec![E::G1Affine::default(); vk.cs().num_advice_columns()]; num_proofs];
		let mut challenges = vec![E::Scalar::zero(); vk.cs().num_challenges()];

		for current_phase in vk.cs().phases() {
			for advice_commitments in advice_commitments.iter_mut() {
				for (phase, commitment) in
					vk.cs().advice_column_phase().iter().zip(advice_commitments.iter_mut())
				{
					if current_phase.0 == *phase {
						*commitment = transcript.read_point()?;
					}
				}
			}
			for (phase, challenge) in vk.cs().challenge_phase().iter().zip(challenges.iter_mut()) {
				if current_phase.0 == *phase {
					*challenge = *transcript.squeeze_challenge_scalar::<()>();
				}
			}
		}

		(advice_commitments, challenges)
	};

	// Sample theta challenge for keeping lookup columns linearly independent
	let theta: ChallengeTheta<_> = transcript.squeeze_challenge_scalar();

	let lookups_permuted = (0..num_proofs)
		.map(|_| -> Result<Vec<_>, _> {
			// Hash each lookup permuted commitment
			vk.cs()
				.lookups()
				.iter()
				.map(|argument| argument.read_permuted_commitments(transcript))
				.collect::<Result<Vec<_>, _>>()
		})
		.collect::<Result<Vec<_>, _>>()?;

	// Sample beta challenge
	let beta: ChallengeBeta<_> = transcript.squeeze_challenge_scalar();

	// Sample gamma challenge
	let gamma: ChallengeGamma<_> = transcript.squeeze_challenge_scalar();

	let permutations_committed = (0..num_proofs)
		.map(|_| {
			// Hash each permutation product commitment
			vk.cs().permutation().read_product_commitments(&vk, transcript)
		})
		.collect::<Result<Vec<_>, _>>()?;

	let lookups_committed = lookups_permuted
		.into_iter()
		.map(|lookups| {
			// Hash each lookup product commitment
			lookups
				.into_iter()
				.map(|lookup| lookup.read_product_commitment(transcript))
				.collect::<Result<Vec<_>, _>>()
		})
		.collect::<Result<Vec<_>, _>>()?;

	let vanishing = vanishing::Argument::read_commitments_before_y(transcript)?;

	// Sample y challenge, which keeps the gates linearly independent.
	let y: ChallengeY<_> = transcript.squeeze_challenge_scalar();

	let vanishing = vanishing.read_commitments_after_y(&vk, transcript)?;

	// Sample x challenge, which is used to ensure the circuit is
	// satisfied with high probability.
	let x: ChallengeX<_> = transcript.squeeze_challenge_scalar();
	let xn = x.pow(&[params.n(), 0, 0, 0]);
	let (min_rotation, max_rotation) =
		vk.cs().instance_queries().iter().fold((0, 0), |(min, max), (_, rotation)| {
			if rotation.0 < min {
				(rotation.0, max)
			} else if rotation.0 > max {
				(min, rotation.0)
			} else {
				(min, max)
			}
		});
	let max_instance_len = instances
		.iter()
		.flat_map(|instance| instance.iter().map(|instance| instance.len()))
		.max_by(Ord::cmp)
		.unwrap_or_default();
	let l_i_s = &vk.get_domain().l_i_range(
		*x,
		xn,
		-max_rotation..max_instance_len as i32 + min_rotation.abs(),
	);
	let instance_evals = instances
		.iter()
		.map(|instances| {
			vk.cs()
				.instance_queries()
				.iter()
				.map(|(column, rotation)| {
					let instances = instances[column.index()];
					let offset = (max_rotation - rotation.0) as usize;
					compute_inner_product(instances, &l_i_s[offset..offset + instances.len()])
				})
				.collect::<Vec<_>>()
		})
		.collect::<Vec<_>>();

	let advice_evals = (0..num_proofs)
		.map(|_| -> Result<Vec<_>, _> {
			read_n_scalars(transcript, vk.cs().advice_queries().len())
		})
		.collect::<Result<Vec<_>, _>>()?;

	let fixed_evals = read_n_scalars(transcript, vk.cs().fixed_queries().len())?;

	let vanishing = vanishing.evaluate_after_x(transcript)?;

	let permutations_common = vk.permutation().evaluate(transcript)?;

	let permutations_evaluated = permutations_committed
		.into_iter()
		.map(|permutation| permutation.evaluate(transcript))
		.collect::<Result<Vec<_>, _>>()?;

	let lookups_evaluated = lookups_committed
		.into_iter()
		.map(|lookups| -> Result<Vec<_>, _> {
			lookups
				.into_iter()
				.map(|lookup| lookup.evaluate(transcript))
				.collect::<Result<Vec<_>, _>>()
		})
		.collect::<Result<Vec<_>, _>>()?;

	// This check ensures the circuit is satisfied so long as the polynomial
	// commitments open to the correct values.
	let vanishing = {
		// x^n
		let xn = x.pow(&[params.n() as u64, 0, 0, 0]);

		let blinding_factors = vk.cs().blinding_factors();
		let l_evals = vk.get_domain().l_i_range(*x, xn, (-((blinding_factors + 1) as i32))..=0);
		assert_eq!(l_evals.len(), 2 + blinding_factors);
		let l_last = l_evals[0];
		let l_blind: E::Scalar = l_evals[1..(1 + blinding_factors)]
			.iter()
			.fold(E::Scalar::zero(), |acc, eval| acc + eval);
		let l_0 = l_evals[1 + blinding_factors];

		// Compute the expected value of h(x)
		let expressions = advice_evals
			.iter()
			.zip(instance_evals.iter())
			.zip(permutations_evaluated.iter())
			.zip(lookups_evaluated.iter())
			.flat_map(|(((advice_evals, instance_evals), permutation), lookups)| {
				let challenges = &challenges;
				let fixed_evals = &fixed_evals;
				std::iter::empty()
					// Evaluate the circuit using the custom gates provided
					.chain(vk.cs().gates().iter().flat_map(move |gate| {
						gate.polynomials().iter().map(move |poly| {
							poly.evaluate(
								&|scalar| scalar,
								&|_| panic!("virtual selectors are removed during optimization"),
								&|query| fixed_evals[query.index()],
								&|query| advice_evals[query.index()],
								&|query| instance_evals[query.index()],
								&|challenge| challenges[challenge.index()],
								&|a| -a,
								&|a, b| a + &b,
								&|a, b| a * &b,
								&|a, scalar| a * &scalar,
							)
						})
					}))
					.chain(permutation.expressions(
						&vk,
						&vk.cs().permutation(),
						&permutations_common,
						advice_evals,
						fixed_evals,
						instance_evals,
						l_0,
						l_last,
						l_blind,
						beta,
						gamma,
						x,
					))
					.chain(
						lookups
							.iter()
							.zip(vk.cs().lookups().iter())
							.flat_map(move |(p, argument)| {
								p.expressions(
									l_0, l_last, l_blind, argument, theta, beta, gamma,
									advice_evals, fixed_evals, instance_evals, challenges,
								)
							})
							.into_iter(),
					)
			});

		vanishing.verify(&params, expressions, y, xn)
	};

	let mut queries: Vec<VerifierQuery<E::G1Affine, MSMKZG<E>>> = Vec::new();

	for (comms, evals) in advice_commitments.iter().zip(advice_evals) {
		for (query_index, &(column, at)) in vk.cs().advice_queries().iter().enumerate() {
			let vq = VerifierQuery::new_commitment(
				&comms[column.index()],
				vk.get_domain().rotate_omega(*x, at),
				evals[query_index],
			);
			queries.push(vq);
		}
	}

	for permutation in permutations_evaluated.iter() {
		let qrs = permutation.queries(&vk, x).clone();
		for q in qrs {
			queries.push(q);
		}
	}

	for lookups in &lookups_evaluated {
		for lookup in lookups {
			let qrs = lookup.queries(&vk, x).clone();
			for q in qrs {
				queries.push(q);
			}
		}
	}

	for (query_index, &(column, at)) in vk.cs().fixed_queries().iter().enumerate() {
		let vq = VerifierQuery::new_commitment(
			&vk.fixed_commitments()[column.index()],
			vk.get_domain().rotate_omega(*x, at),
			fixed_evals[query_index],
		);
		queries.push(vq);
	}

	for q in permutations_common.queries(&vk.permutation(), x) {
		queries.push(q);
	}

	for q in vanishing.queries(x) {
		queries.push(q);
	}

	let mut owned_queries = Vec::new();
	for vq in queries {
		let point = vq.get_point();
		let eval = vq.get_eval();
		let comm = vq.get_commitment();

		let comm_owned = match comm {
			CommitmentReference::Commitment(c) => CommitmentReferenceOwned::Commitment(c.clone()),
			CommitmentReference::MSM(msm) => CommitmentReferenceOwned::MSM(msm.clone()),
		};

		let vq_owned = VerifierQueryOwned { point, eval, commitment: comm_owned };
		owned_queries.push(vq_owned);
	}

	Ok(owned_queries)
}
