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

use constants::{MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS};
use eigen_trust_circuit::{
	halo2wrong::{
		curves::bn256::Bn256,
		halo2::poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
	},
	params::poseidon_bn254_5x5::Params,
	utils::{keygen, random_circuit},
};
use error::EigenError;
use hyper::{
	body::{aggregate, Buf},
	server::conn::Http,
	service::service_fn,
	Body, Method, Request, Response,
};
use manager::{Manager, SignatureData};
use rand::thread_rng;
use serde::{ser::StdError, Deserialize, Serialize};
use serde_json::from_reader;
use std::{
	fmt::{Display, Formatter, Result as FmtResult},
	net::SocketAddr,
	sync::{Arc, Mutex},
};
use tokio::{
	io::{AsyncRead, AsyncWrite},
	net::TcpListener,
	select,
	time::{self, Duration},
};

async fn handle_request(req: Request<Body>) -> Result<Response<String>, EigenError> {
	match (req.method(), req.uri().path()) {
		(&Method::GET, "/score") => {
			let q = req.uri().query();
			let query_string = q.ok_or(EigenError::InvalidQuery)?;
			println!("required pubkey score {:?}", query_string);
		},
		(&Method::POST, "/signature") => {
			// Aggregate the body...
			let whole_body = aggregate(req).await.map_err(|_| EigenError::AggregateBodyError)?;
			// Decode as JSON...
			let data: SignatureData =
				from_reader(whole_body.reader()).map_err(|_| EigenError::ParseError)?;
			println!("posted signature {:?}", data);
		},
		_ => return Err(EigenError::InvalidRequest),
	}
	Ok(Response::new(String::from("Hello World!")))
}

async fn handle_connection<I: AsyncRead + AsyncWrite + Unpin + 'static>(
	stream: I, _addr: SocketAddr,
) {
	let mut https = Http::new();
	https.http1_keep_alive(false);

	let service_function = service_fn(
		async move |req: Request<Body>| -> Result<Response<String>, EigenError> {
			handle_request(req).await
		},
	);
	let res = https.serve_connection(stream, service_function).await;
	if let Err(err) = res {
		println!("Error serving connection: {:?}", err);
	}
}

#[tokio::main]
pub async fn main() -> Result<(), EigenError> {
	let addr: SocketAddr = ([127, 0, 0, 1], 3000).into();

	let listener = TcpListener::bind(addr).await.map_err(|_| EigenError::ListenError)?;
	println!("Listening on https://{}", addr);

	let mut rng = thread_rng();
	let params = ParamsKZG::new(9);
	let random_circuit =
		random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params>(&mut rng);
	let pk = keygen(&params, &random_circuit).unwrap();

	let manager = Arc::new(Mutex::new(Manager::new(params, pk)));
	let res = manager.lock();

	let interval = Duration::from_secs(2);
	let mut inner_interval = time::interval(interval);
	inner_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

	loop {
		select! {
			res = listener.accept() => {
				let (stream, addr) = res.map_err(|_| EigenError::ConnectionError)?;
				handle_connection(stream, addr).await;
			}
			res = inner_interval.tick() => {
				println!("{:?}", res);
			}
		};
	}
}
