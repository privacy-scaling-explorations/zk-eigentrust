//! # Eigen Trust
//!
//! A library for managing trust in a distributed network with zero-knowledge
//! features.
//!
//! ## Main characteristics:
//! **Self-policing** - the shared ethics of the user population is defined and
//! enforced by the peers themselves and not by some central authority.
//!
//! **Minimal** - computation, infrastructure, storage, and message complexity
//! are reduced to a minimum.
//!
//! **Incorruptible** - Reputation should be obtained by consistent good
//! behavior through several transactions. This is enforced for all users, so no
//! one can cheat the system and obtain a higher reputation. It is also
//! resistant to malicious collectives.
//!
//! ## Implementation
//! The library is implemented according to the original [Eigen Trust paper](http://ilpubs.stanford.edu:8090/562/1/2002-56.pdf).
//! It is developed under the Ethereum Foundation grant.

#![feature(async_closure)]
#![feature(array_zip, array_try_map)]
#![allow(clippy::tabs_in_doc_comments)]
#![deny(
	future_incompatible, nonstandard_style, deprecated, unreachable_code, unreachable_patterns,
	absolute_paths_not_starting_with_crate, unsafe_code, clippy::panic, clippy::unnecessary_cast,
	clippy::cast_lossless, clippy::cast_possible_wrap
)]
#![warn(trivial_casts)]
#![forbid(unsafe_code)]

/// The module for global constants.
pub mod constants;
/// The module for epoch-related calculations, like seconds until the next
/// epoch, current epoch, etc.
pub mod epoch;
/// The module where the error enum is defined
pub mod error;
/// The module for the manager related functionalities, like:
/// - Adding/removing neighbors of peers
/// - Calculating the score of peers
/// - Keeping track of neighbors scores towards us
pub mod manager;
/// Common utility functions used across the crate
pub mod utils;

use constants::{EPOCH_INTERVAL, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, NUM_ITERATIONS};
use eigen_trust_circuit::{
	halo2wrong::{
		curves::{
			bn256::{Bn256, Fr as Bn265Scalar},
			group::ff::PrimeField,
		},
		halo2::poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
	},
	params::poseidon_bn254_5x5::Params,
	utils::{keygen, random_circuit},
};
use epoch::Epoch;
use error::EigenError;
use hyper::{
	body::{aggregate, Buf},
	server::conn::{AddrStream, Http},
	service::{make_service_fn, service_fn},
	Body, Method, Request, Response, StatusCode,
};
use manager::{
	sig::{Signature, SignatureData},
	Manager,
};
use once_cell::sync::Lazy;
use rand::thread_rng;
use serde::{ser::StdError, Deserialize, Serialize};
use serde_json::{from_reader, Error as SerdeError, Result as SerdeResult};
use std::{
	fmt::{Display, Formatter, Result as FmtResult},
	net::SocketAddr,
	sync::{Arc, Mutex, MutexGuard, PoisonError},
};
use tokio::{
	io::{AsyncRead, AsyncWrite},
	net::TcpListener,
	select,
	time::{self, Duration},
};
use utils::{generate_pk_from_sk, scalar_from_bs58};

const BAD_REQUEST: u16 = 400;
const NOT_FOUND: u16 = 404;
const INTERNAL_SERVER_ERROR: u16 = 500;

#[derive(Debug)]
enum ResponseBody {
	SignatureAddSuccess,
	Score(f64),
	LockError,
	InvalidQuery,
	InvalidRequest,
}

impl ToString for ResponseBody {
	fn to_string(&self) -> String {
		match self {
			ResponseBody::SignatureAddSuccess => "SignatureAddSuccess".to_string(),
			ResponseBody::Score(s) => s.to_string(),
			ResponseBody::LockError => "LockError".to_string(),
			ResponseBody::InvalidQuery => "InvalidQuery".to_string(),
			ResponseBody::InvalidRequest => "InvalidRequest".to_string(),
		}
	}
}

static MANAGER_STORE: Lazy<Arc<Mutex<Manager>>> = Lazy::new(|| {
	let mut rng = thread_rng();
	let params = ParamsKZG::new(9);
	let random_circuit =
		random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params>(&mut rng);
	let proving_key = keygen(&params, &random_circuit).unwrap();

	Arc::new(Mutex::new(Manager::new(params, proving_key)))
});

async fn handle_request(
	req: Request<Body>, arc_manager: Arc<Mutex<Manager>>,
) -> Result<Response<String>, EigenError> {
	match (req.method(), req.uri().path()) {
		(&Method::GET, "/score") => {
			let q = req.uri().query();
			if q.is_none() {
				let res = Response::builder()
					.status(BAD_REQUEST)
					.body(ResponseBody::InvalidQuery.to_string())
					.unwrap();
				return Ok(res);
			}
			let query_string = q.unwrap();
			let pk = Bn265Scalar::from_str_vartime(query_string);
			if pk.is_none() {
				let res = Response::builder()
					.status(BAD_REQUEST)
					.body(ResponseBody::InvalidQuery.to_string())
					.unwrap();
				return Ok(res);
			}
			let manager = arc_manager.lock();
			if manager.is_err() {
				let e = manager.err();
				let res = Response::builder()
					.status(INTERNAL_SERVER_ERROR)
					.body(ResponseBody::LockError.to_string())
					.unwrap();
				return Ok(res);
			}
			let mut m = manager.unwrap();
			let pk = pk.unwrap();
			let sig = m.get_signature(&pk);
			let last_epoch = Epoch::current_epoch(EPOCH_INTERVAL).previous();
			let ops = m.get_op_jis(sig, last_epoch, NUM_ITERATIONS);
			let ops_sum: f64 = ops.iter().sum();
			let res = Response::new(ResponseBody::Score(ops_sum).to_string());
			return Ok(res);
		},
		(&Method::POST, "/signature") => {
			// Aggregate the body...
			let whole_body = aggregate(req).await;
			if whole_body.is_err() {
				let res = Response::builder()
					.status(BAD_REQUEST)
					.body(ResponseBody::InvalidQuery.to_string())
					.unwrap();
				return Ok(res);
			}
			let whole_body = whole_body.unwrap();
			// Decode as JSON...
			let data: SerdeResult<SignatureData> = from_reader(whole_body.reader());
			if data.is_err() {
				let res = Response::builder()
					.status(BAD_REQUEST)
					.body(ResponseBody::InvalidQuery.to_string())
					.unwrap();
				return Ok(res);
			}
			let manager = arc_manager.lock();
			if manager.is_err() {
				let e = manager.err();
				let res = Response::builder()
					.status(INTERNAL_SERVER_ERROR)
					.body(ResponseBody::LockError.to_string())
					.unwrap();
				return Ok(res);
			}
			let mut m = manager.unwrap();
			let data = data.unwrap();
			let sig: Signature = data.clone().into();
			m.add_signature(sig);
			let res = ResponseBody::SignatureAddSuccess;
			return Ok(Response::new(res.to_string()));
		},
		_ => {
			return Ok(Response::builder()
				.status(NOT_FOUND)
				.body(ResponseBody::InvalidRequest.to_string())
				.unwrap())
		},
	}
}

async fn handle_connection<I: AsyncRead + AsyncWrite + Unpin + 'static>(
	stream: I, _addr: SocketAddr,
) {
	let mut https = Http::new();
	https.http1_keep_alive(false);

	let service_function = service_fn(async move |req| {
		let mng_store = Arc::clone(&MANAGER_STORE);
		handle_request(req, mng_store).await
	});
	let res = https.serve_connection(stream, service_function).await;
	if let Err(err) = res {
		println!("Error serving connection: {:?}", err);
	}
}

fn handle_epoch_convergence(
	manager: Result<MutexGuard<Manager>, PoisonError<MutexGuard<Manager>>>,
) {
	if manager.is_err() {
		let e = manager.err();
		println!("error: {:?}", e);
		return;
	}

	let mut manager = manager.unwrap();

	let epoch = Epoch::current_epoch(EPOCH_INTERVAL);
	manager.calculate_initial_ivps(epoch);

	for i in 0..NUM_ITERATIONS {
		manager.calculate_ivps(epoch, i);
	}
}

#[tokio::main]
pub async fn main() -> Result<(), EigenError> {
	let addr: SocketAddr = ([127, 0, 0, 1], 3000).into();

	let listener = TcpListener::bind(addr).await.map_err(|_| EigenError::ListenError)?;
	println!("Listening on https://{}", addr);

	let interval = Duration::from_secs(EPOCH_INTERVAL);
	let mut inner_interval = time::interval(interval);
	inner_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

	loop {
		select! {
			res = listener.accept() => {
				let (stream, addr) = res.map_err(|_| EigenError::ConnectionError)?;
				handle_connection(stream, addr).await;
			}
			res = inner_interval.tick() => {
				let manager = MANAGER_STORE.lock();
				handle_epoch_convergence(manager);
			}
		};
	}
}
