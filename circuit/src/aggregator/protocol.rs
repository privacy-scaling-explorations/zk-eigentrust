/*

Domain {
	k: 4,
	n: 16,
	n_inv: 0x2d5e098bb31e86271ccb415b196942d755b0a9c3f21dd9882fa3d63ab1000001,
	gen: 0x21082ca216cbbf4e1c6e4f4594dd508c996dfbe1174efb98b11509c6e306460b,
	gen_inv: 0x02e40daf409556c02bfc85eb303402b774954d30aeb0337eb85a71e6373428de,
}
Preprocessed = [
	(0x20a43e7c9b0bfed89242523c32d315f2f730b71e1fdc2ffae0d41960c74a9bb9, 0x1f031b066e41eb70f097b18b47ce89b9cde78886fd22df24a3f2b7f42c94a7e5),
]
num_instance = [ 1, 1, ]
num_witness = [ 6, 0, 7, ]
num_challenge = [ 1, 2, 1, ]
Evaluations = [
	Query { poly: 3, rotation: Rotation(0,) },
	Query { poly: 4, rotation: Rotation(0) },
	Query { poly: 3, rotation: Rotation(1) },
	Query { poly: 5, rotation: Rotation(0) },
	Query { poly: 6, rotation: Rotation(0) },
	Query { poly: 5, rotation: Rotation(1) },
	Query {poly: 0, rotation: Rotation(0) },
	Query {poly: 7, rotation: Rotation(0) },
]
Queries = [
	Query { poly: 3, rotation: Rotation(0) },
	Query { poly: 4, rotation: Rotation(0) },
	Query {poly: 3, rotation: Rotation(1) },
	Query { poly: 5, rotation: Rotation(0) },
	Query { poly: 6, rotation: Rotation(0) },
	Query { poly: 5, rotation: Rotation(1) },
	Query { poly: 0, rotation: Rotation(0) },
	Query { poly: 8, rotation: Rotation(0) },
	Query {poly: 7 rotation: Rotation(0) },
]

Quotient = QuotientPolynomial {
	chunk_degree: 1,
	numerator: DistributePowers(
		[
			Product(
				Polynomial(Query { poly: 0, rotation: Rotation(0) }),
				Sum(
					Product(
						Polynomial(Query { poly: 3, rotation: Rotation(0) }),
						Polynomial(Query { poly: 4, rotation: Rotation(0) }),
					),
					Negated(Polynomial(Query {poly: 3, rotation: Rotation(1) })),
				),
			),
			Product(
				Polynomial(Query { poly: 0, rotation: Rotation(0) }),
				Sum(
					Product(
						Polynomial(Query { poly: 5, rotation: Rotation(0) }),
						Polynomial(Query { poly: 6, rotation: Rotation(0) }),
					),
					Negated(Polynomial(Query { poly: 5, rotation: Rotation(1) })),
				),
			),
		],
		Challenge(
			3,
		),
	),
}
transcript_initial_state = Some(
	0x021fc4f2493918b9764ac35a03ec3b92ae1daf3ea4ab4590b17329bfb1419ff1,
)
instance_committing_key = Some(
	InstanceCommittingKey {
		bases: [
			(0x20a43e7c9b0bfed89242523c32d315f2f730b71e1fdc2ffae0d41960c74a9bb9, 0x1f031b066e41eb70f097b18b47ce89b9cde78886fd22df24a3f2b7f42c94a7e5),
		],
		constant: Some(
			(0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed, 0x26d51731bc1ba9e2ffea9d872dabd5660c45a1b4330ca4373e66fab49c3b4dda),
		),
	},
)
linearization = None
accumulator_indices = [[(0, 0), (0, 1), (0, 2), (0, 3)], [(1, 0), (1, 1), (1, 2), (1, 3)]]

*/

use crate::aggregator::protocol::Expression::{Challenge, Negated, Polynomial, Product, Sum};

use halo2wrong::curves::{
	bn256::{Fq, Fr, G1Affine},
	group::ff::PrimeField,
	CurveAffine, FieldExt,
};
use std::cmp::max;

#[derive(Debug)]
pub struct Domain<F: PrimeField> {
	k: usize,
	n: usize,
	n_inv: F,
	gen: F,
	gen_inv: F,
}

#[derive(Debug)]
pub struct InstanceCommittingKey<C> {
	pub bases: Vec<C>,
	pub constant: Option<C>,
}

#[derive(Clone, Debug)]
pub enum Expression<F> {
	Constant(F),
	Polynomial(Query),
	Challenge(usize),
	Negated(Box<Expression<F>>),
	Sum(Box<Expression<F>>, Box<Expression<F>>),
	Product(Box<Expression<F>>, Box<Expression<F>>),
}

impl<F: Clone> Expression<F> {
	pub fn degree(&self) -> usize {
		match self {
			Expression::Constant(_) => 0,
			Expression::Polynomial { .. } => 1,
			Expression::Challenge { .. } => 0,
			Expression::Negated(a) => a.degree(),
			Expression::Sum(a, b) => max(a.degree(), b.degree()),
			Expression::Product(a, b) => a.degree() + b.degree(),
		}
	}
}

#[derive(Clone, Debug)]
pub struct QuotientPolynomial<F: Clone> {
	pub chunk_degree: usize,
	pub numerator: Expression<F>,
}

#[derive(Clone, Debug)]
pub struct Query {
	pub poly: usize,
	pub rotation: Rotation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rotation(pub i32);

impl Rotation {
	pub fn cur() -> Self {
		Rotation(0)
	}

	pub fn prev() -> Self {
		Rotation(-1)
	}

	pub fn next() -> Self {
		Rotation(1)
	}
}

pub trait Protocol<F: FieldExt, G: CurveAffine> {
	fn domain() -> Domain<G::Scalar>;
	fn preprocessed() -> [G; 1];
	fn evaluations() -> Vec<Query>;
	fn queries() -> Vec<Query>;
	fn relations() -> Vec<Expression<G::Scalar>>;
	fn num_instance() -> Vec<usize>;
	fn num_witness() -> Vec<usize>;
	fn num_challenge() -> Vec<usize>;
	fn transcript_initial_state() -> Option<F>;
	fn instance_committing_key() -> Option<InstanceCommittingKey<G>>;
	fn linearization() -> Option<F>;
	fn accumulator_indices() -> Vec<Vec<(usize, usize)>>;
	fn vanishing_poly() -> usize;
}

pub struct FixedProtocol;

impl Protocol<Fr, G1Affine> for FixedProtocol {
	fn domain() -> Domain<Fr> {
		Domain {
			k: 4,
			n: 16,
			n_inv: Fr::from_str_vartime(
				"20520227692349320520856005386178695395514091625390032197217066424914820464641",
			)
			.unwrap(),
			gen: Fr::from_str_vartime(
				"14940766826517323942636479241147756311199852622225275649687664389641784935947",
			)
			.unwrap(),
			gen_inv: Fr::from_str_vartime(
				"1307561275430600547084599052067232502310777467428991595475612152992795732190",
			)
			.unwrap(),
		}
	}

	fn preprocessed() -> [G1Affine; 1] {
		let limb = G1Affine {
			x: Fq::from_str_vartime(
				"14764205340923407067494665187018826350036683153215054852217170390603606432697",
			)
			.unwrap(),
			y: Fq::from_str_vartime(
				"14027185367798106412660765956500198968993654087248532351926754678141225314277",
			)
			.unwrap(),
		};
		[limb]
	}

	fn evaluations() -> Vec<Query> {
		vec![
			Query { poly: 3, rotation: Rotation(0) },
			Query { poly: 4, rotation: Rotation(0) },
			Query { poly: 3, rotation: Rotation(1) },
			Query { poly: 5, rotation: Rotation(0) },
			Query { poly: 6, rotation: Rotation(0) },
			Query { poly: 5, rotation: Rotation(1) },
			Query { poly: 0, rotation: Rotation(0) },
			Query { poly: 7, rotation: Rotation(0) },
		]
	}

	fn queries() -> Vec<Query> {
		vec![
			Query { poly: 3, rotation: Rotation(0) },
			Query { poly: 4, rotation: Rotation(0) },
			Query { poly: 3, rotation: Rotation(1) },
			Query { poly: 5, rotation: Rotation(0) },
			Query { poly: 6, rotation: Rotation(0) },
			Query { poly: 5, rotation: Rotation(1) },
			Query { poly: 0, rotation: Rotation(0) },
			Query { poly: 8, rotation: Rotation(0) },
			Query { poly: 7, rotation: Rotation(0) },
		]
	}

	fn relations() -> Vec<Expression<Fr>> {
		vec![
			Product(
				Box::new(Polynomial(Query { poly: 0, rotation: Rotation(0) })),
				Box::new(Sum(
					Box::new(Product(
						Box::new(Polynomial(Query { poly: 3, rotation: Rotation(0) })),
						Box::new(Polynomial(Query { poly: 4, rotation: Rotation(0) })),
					)),
					Box::new(Negated(Box::new(Polynomial(Query {
						poly: 3,
						rotation: Rotation(1),
					})))),
				)),
			),
			Product(
				Box::new(Polynomial(Query { poly: 0, rotation: Rotation(0) })),
				Box::new(Sum(
					Box::new(Product(
						Box::new(Polynomial(Query { poly: 5, rotation: Rotation(0) })),
						Box::new(Polynomial(Query { poly: 6, rotation: Rotation(0) })),
					)),
					Box::new(Negated(Box::new(Polynomial(Query {
						poly: 5,
						rotation: Rotation(1),
					})))),
				)),
			),
		]
	}

	fn num_instance() -> Vec<usize> {
		vec![1, 1]
	}

	fn num_witness() -> Vec<usize> {
		vec![6, 0, 7]
	}

	fn num_challenge() -> Vec<usize> {
		vec![1, 2, 1]
	}

	fn transcript_initial_state() -> Option<Fr> {
		Fr::from_str_vartime(
			"960757230477012554344795604571921715026536479591820127796550211942517678065",
		)
	}

	fn instance_committing_key() -> Option<InstanceCommittingKey<G1Affine>> {
		Some(InstanceCommittingKey {
			bases: vec![G1Affine {
				x: Fq::from_str_vartime(
					"14764205340923407067494665187018826350036683153215054852217170390603606432697",
				)
				.unwrap(),
				y: Fq::from_str_vartime(
					"14027185367798106412660765956500198968993654087248532351926754678141225314277",
				)
				.unwrap(),
			}],
			constant: Some(G1Affine {
				x: Fq::from_str_vartime(
					"10857046999023057135944570762232829481370756359578518086990519993285655852781",
				)
				.unwrap(),
				y: Fq::from_str_vartime(
					"17564386751975372480616216091948734478118213282077321509066424171737464393178",
				)
				.unwrap(),
			}),
		})
	}

	fn linearization() -> Option<Fr> {
		None
	}

	fn accumulator_indices() -> Vec<Vec<(usize, usize)>> {
		vec![vec![(0, 0), (0, 1), (0, 2), (0, 3)], vec![(1, 0), (1, 1), (1, 2), (1, 3)]]
	}

	fn vanishing_poly() -> usize {
		Self::preprocessed().len()
			+ Self::num_instance().len()
			+ Self::num_witness().iter().sum::<usize>()
	}
}

#[test]
fn test_output() {
	println!("{:#?}", FixedProtocol::domain());
	println!("{:#?}", FixedProtocol::preprocessed());
	println!("{:#?}", FixedProtocol::evaluations());
	println!("{:#?}", FixedProtocol::queries());
	println!("{:#?}", FixedProtocol::quotient());
	println!("{:#?}", FixedProtocol::num_challenge());
	println!("{:#?}", FixedProtocol::num_instance());
	println!("{:#?}", FixedProtocol::num_witness());
	println!("{:#?}", FixedProtocol::accumulator_indices());
	println!("{:#?}", FixedProtocol::linearization());
	println!("{:#?}", FixedProtocol::instance_committing_key());
	println!("{:#?}", FixedProtocol::transcript_initial_state());
}
