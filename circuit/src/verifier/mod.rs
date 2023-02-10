use std::fmt::Debug;

use crate::verifier::queries::CommitmentReferenceOwned;

use self::{queries::CommitmentData, transcript::PoseidonRead};
use halo2::{
	arithmetic::{powers, Field},
	halo2curves::{
		pairing::{Engine, MultiMillerLoop},
		serde::SerdeObject,
	},
	poly::{
		commitment::{ParamsProver, MSM},
		kzg::{
			commitment::ParamsKZG,
			msm::{DualMSM, MSMKZG},
			strategy::GuardKZG,
		},
		Error,
	},
	transcript::{ChallengeScalar, EncodedChallenge, Transcript, TranscriptRead},
};

/// Some queries idk
pub mod queries;
/// Multi-scalar multiplication
// pub mod msm;
/// Poseidon transcript
pub mod transcript;

#[derive(Clone, Copy, Debug)]
struct U {}
#[derive(Clone, Copy, Debug)]
struct V {}

#[derive(Debug)]
/// Concrete KZG verifier with GWC variant
pub struct VerifierGWC<'params, E: Engine> {
	params: &'params ParamsKZG<E>,
}

impl<'params, E> VerifierGWC<'params, E>
where
	E: MultiMillerLoop + Debug,
	E::G1Affine: SerdeObject,
	E::G2Affine: SerdeObject,
{
	fn new(params: &'params ParamsKZG<E>) -> Self {
		Self { params }
	}

	fn verify_proof<Ch: EncodedChallenge<E::G1Affine>, I>(
		&self, transcript: &mut PoseidonRead<E::G1Affine>, commitment_data: Vec<CommitmentData<E>>,
		mut msm_accumulator: DualMSM<'params, E>,
	) -> Result<GuardKZG<'params, E>, Error> {
		let v: ChallengeScalar<E::G1Affine, V> = transcript.squeeze_challenge_scalar();

		let w: Vec<E::G1Affine> = (0..commitment_data.len())
			.map(|_| transcript.read_point().map_err(|_| Error::SamplingError))
			.collect::<Result<Vec<E::G1Affine>, Error>>()?;

		let u: ChallengeScalar<E::G1Affine, U> = transcript.squeeze_challenge_scalar();

		let mut commitment_multi = MSMKZG::<E>::new();
		let mut eval_multi = E::Scalar::zero();

		let mut witness = MSMKZG::<E>::new();
		let mut witness_with_aux = MSMKZG::<E>::new();

		for ((commitment_at_a_point, wi), power_of_u) in
			commitment_data.iter().zip(w.into_iter()).zip(powers(*u))
		{
			assert!(!commitment_at_a_point.queries.is_empty());
			let z = commitment_at_a_point.point;

			let (mut commitment_batch, eval_batch) = commitment_at_a_point
				.queries
				.iter()
				.zip(powers(*v))
				.map(|(query, power_of_v)| {
					assert_eq!(query.get_point(), z);

					let commitment = match query.get_commitment() {
						CommitmentReferenceOwned::Commitment(c) => {
							let mut msm = MSMKZG::<E>::new();
							msm.append_term(power_of_v, c.into());
							msm
						},
						CommitmentReferenceOwned::MSM(msm) => {
							let mut msm = msm.clone();
							msm.scale(power_of_v);
							msm
						},
					};
					let eval = power_of_v * query.get_eval();

					(commitment, eval)
				})
				.reduce(|(mut commitment_acc, eval_acc), (commitment, eval)| {
					commitment_acc.add_msm(&commitment);
					(commitment_acc, eval_acc + eval)
				})
				.unwrap();

			commitment_batch.scale(power_of_u);
			commitment_multi.add_msm(&commitment_batch);
			eval_multi += power_of_u * eval_batch;

			witness_with_aux.append_term(power_of_u * z, wi.into());
			witness.append_term(power_of_u, wi.into());
		}

		msm_accumulator.left.add_msm(&witness);

		msm_accumulator.right.add_msm(&witness_with_aux);
		msm_accumulator.right.add_msm(&commitment_multi);
		let g0: E::G1 = self.params.get_g()[0].into();
		msm_accumulator.right.append_term(eval_multi, -g0);

		Ok(GuardKZG::new(msm_accumulator))
	}
}
