#![feature(async_closure)]

use hyper::{
	body::{aggregate, Buf},
	server::conn::Http,
	service::service_fn,
	Body, Method, Request, Response,
};
use once_cell::sync::Lazy;
use rand::thread_rng;
use serde_json::{from_reader, to_string, Result as SerdeResult};
use std::{
	collections::HashMap,
	mem::drop,
	net::SocketAddr,
	sync::{Arc, Mutex},
};
use tokio::{
	io::{AsyncRead, AsyncWrite},
	net::TcpListener,
	select,
	time::{self, Duration},
};

use eigen_trust_circuit::{
	circuit::EigenTrust,
	halo2::{
		halo2curves::{bn256::Fr as Scalar, group::ff::PrimeField},
		poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
	},
	utils::{keygen, to_short},
};
use eigen_trust_protocol::{
	epoch::Epoch,
	error::EigenError,
	manager::{
		attestation::{Attestation, AttestationData},
		Manager, Proof, INITIAL_SCORE, NUM_ITER, NUM_NEIGHBOURS, SCALE,
	},
};

const BAD_REQUEST: u16 = 400;
const NOT_FOUND: u16 = 404;
const INTERNAL_SERVER_ERROR: u16 = 500;

#[derive(Debug)]
enum ResponseBody {
	AttestationAddSuccess,
	Score(Proof),
	LockError,
	InvalidQuery,
	InvalidRequest,
}

impl ToString for ResponseBody {
	fn to_string(&self) -> String {
		match self {
			ResponseBody::AttestationAddSuccess => "AttestationAddSuccess".to_string(),
			ResponseBody::Score(proof) => to_string(&proof).unwrap(),
			ResponseBody::LockError => "LockError".to_string(),
			ResponseBody::InvalidQuery => "InvalidQuery".to_string(),
			ResponseBody::InvalidRequest => "InvalidRequest".to_string(),
		}
	}
}

struct Query {
	pk: Scalar,
	epoch: Epoch,
}

impl Query {
	pub fn parse(query_string: &str) -> Option<Query> {
		let parts: Vec<&str> = query_string.split("&").into_iter().collect();
		if parts.len() != 2 {
			return None;
		}

		let mut map = HashMap::new();
		for part in parts {
			let pair: Vec<&str> = part.split("=").into_iter().collect();
			if pair.len() != 2 {
				return None;
			}
			map.insert(pair[0], pair[1]);
		}

		let pk = map.get("pk");
		let epoch = map.get("epoch");
		if pk.is_none() || epoch.is_none() {
			return None;
		}

		let pk_bytes = bs58::decode(pk.unwrap()).into_vec();
		if pk_bytes.is_err() {
			return None;
		}
		let pk_bytes = to_short(&pk_bytes.unwrap());
		let pk_scalar = Scalar::from_repr(pk_bytes).unwrap();
		let epoch_res: Result<u64, _> = epoch.unwrap().parse();
		if epoch_res.is_err() {
			return None;
		}
		let epoch = Epoch(epoch_res.unwrap());

		Some(Query { pk: pk_scalar, epoch })
	}
}

static MANAGER_STORE: Lazy<Arc<Mutex<Manager>>> = Lazy::new(|| {
	let mut rng = thread_rng();
	let params = ParamsKZG::new(14);
	let random_circuit =
		EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::random(&mut rng);
	let proving_key = keygen(&params, random_circuit).unwrap();

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
			let query = Query::parse(query_string);
			if query.is_none() {
				let res = Response::builder()
					.status(BAD_REQUEST)
					.body(ResponseBody::InvalidQuery.to_string())
					.unwrap();
				return Ok(res);
			}
			let query = query.unwrap();
			let manager = arc_manager.lock();
			if manager.is_err() {
				let res = Response::builder()
					.status(INTERNAL_SERVER_ERROR)
					.body(ResponseBody::LockError.to_string())
					.unwrap();
				return Ok(res);
			}
			let m = manager.unwrap();
			let proof = m.get_proof(query.epoch);
			if proof.is_err() {
				println!("{:?}", proof.err().unwrap());
				let res = Response::builder()
					.status(BAD_REQUEST)
					.body(ResponseBody::InvalidQuery.to_string())
					.unwrap();
				return Ok(res);
			}
			let proof = proof.unwrap();
			let res = Response::new(ResponseBody::Score(proof).to_string());
			return Ok(res);
		},
		(&Method::POST, "/attestation") => {
			// Aggregate the body...
			let whole_body = aggregate(req).await;
			if whole_body.is_err() {
				let res = Response::builder()
					.status(BAD_REQUEST)
					.body(ResponseBody::InvalidRequest.to_string())
					.unwrap();
				return Ok(res);
			}
			let whole_body = whole_body.unwrap();
			// Decode as JSON...
			let data: SerdeResult<AttestationData> = from_reader(whole_body.reader());
			if data.is_err() {
				let res = Response::builder()
					.status(BAD_REQUEST)
					.body(ResponseBody::InvalidRequest.to_string())
					.unwrap();
				return Ok(res);
			}
			let manager = arc_manager.lock();
			if manager.is_err() {
				let res = Response::builder()
					.status(INTERNAL_SERVER_ERROR)
					.body(ResponseBody::LockError.to_string())
					.unwrap();
				return Ok(res);
			}
			let mut m = manager.unwrap();
			let data = data.unwrap();
			let sig: Attestation = data.clone().into();
			m.add_attestation(sig);
			let res = ResponseBody::AttestationAddSuccess;
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

fn handle_epoch_convergence(arc_manager: Arc<Mutex<Manager>>, epoch: Epoch) {
	let manager = arc_manager.lock();

	if manager.is_err() {
		let e = manager.err();
		println!("error: {:?}", e);
		return;
	}

	let mut manager = manager.unwrap();
	manager.calculate_proofs(epoch).unwrap();
}

#[tokio::main]
async fn main() -> Result<(), EigenError> {
	let addr: SocketAddr = ([127, 0, 0, 1], 3000).into();

	let listener = TcpListener::bind(addr).await.map_err(|_| EigenError::ListenError)?;
	println!("Listening on https://{}", addr);

	const EPOCH_INTERVAL: u64 = 10;
	let interval = Duration::from_secs(EPOCH_INTERVAL);
	let mut inner_interval = time::interval(interval);
	inner_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

	let mng_store = Arc::clone(&MANAGER_STORE);
	let mut manager = mng_store.lock().unwrap();
	manager.generate_initial_attestations();
	drop(manager);

	loop {
		select! {
			res = listener.accept() => {
				let (stream, addr) = res.map_err(|_| EigenError::ConnectionError)?;
				handle_connection(stream, addr).await;
			}
			_res = inner_interval.tick() => {
				let epoch = Epoch::current_epoch(EPOCH_INTERVAL);
				handle_epoch_convergence(mng_store.clone(), epoch);
			}
		};
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use eigen_trust_circuit::{
		calculate_message_hash,
		eddsa::native::sign,
		halo2::{arithmetic::FieldExt, halo2curves::bn256::Fr as Scalar},
	};
	use eigen_trust_protocol::{manager::FIXED_SET, utils::keyset_from_raw};
	use hyper::Uri;
	use serde_json::to_vec;

	#[tokio::test]
	async fn should_fail_without_query() {
		let mut rng = thread_rng();
		let params = ParamsKZG::new(14);
		let random_circuit =
			EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::random(&mut rng);
		let proving_key = keygen(&params, random_circuit).unwrap();

		let manager = Manager::new(params, proving_key);
		let arc_manager = Arc::new(Mutex::new(manager));

		let req = Request::get(Uri::from_static("http://localhost:3000/score"))
			.body(Body::default())
			.unwrap();

		let res = handle_request(req, arc_manager).await.unwrap();
		assert_eq!(*res.body(), ResponseBody::InvalidQuery.to_string());
	}

	#[tokio::test]
	async fn should_fail_with_wrong_public_key() {
		let mut rng = thread_rng();
		let params = ParamsKZG::new(14);
		let random_circuit =
			EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::random(&mut rng);
		let proving_key = keygen(&params, random_circuit).unwrap();

		let manager = Manager::new(params, proving_key);
		let arc_manager = Arc::new(Mutex::new(manager));

		let req = Request::get(Uri::from_static(
			"http://localhost:3000/score?pk=abcd__123&epoch=123",
		))
		.body(Body::default())
		.unwrap();

		let res = handle_request(req, arc_manager).await.unwrap();
		assert_eq!(*res.body(), ResponseBody::InvalidQuery.to_string());
	}

	#[tokio::test]
	async fn should_fail_with_wrong_epoch() {
		let mut rng = thread_rng();
		let params = ParamsKZG::new(14);
		let random_circuit =
			EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::random(&mut rng);
		let proving_key = keygen(&params, random_circuit).unwrap();

		let manager = Manager::new(params, proving_key);
		let arc_manager = Arc::new(Mutex::new(manager));

		let req = Request::get(Uri::from_static(
			"http://localhost:3000/score?pk=abcd123&epoch=abc",
		))
		.body(Body::default())
		.unwrap();

		let res = handle_request(req, arc_manager).await.unwrap();
		assert_eq!(*res.body(), ResponseBody::InvalidQuery.to_string());
	}

	#[tokio::test]
	async fn should_fail_with_incomplete_query() {
		let mut rng = thread_rng();
		let params = ParamsKZG::new(14);
		let random_circuit =
			EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::random(&mut rng);
		let proving_key = keygen(&params, random_circuit).unwrap();

		let manager = Manager::new(params, proving_key);
		let arc_manager = Arc::new(Mutex::new(manager));

		let req = Request::get(Uri::from_static("http://localhost:3000/score?pk=abcd123"))
			.body(Body::default())
			.unwrap();

		let res = handle_request(req, arc_manager).await.unwrap();
		assert_eq!(*res.body(), ResponseBody::InvalidQuery.to_string());
	}

	#[tokio::test]
	async fn should_fail_if_route_is_not_found() {
		let mut rng = thread_rng();
		let params = ParamsKZG::new(14);
		let random_circuit =
			EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::random(&mut rng);
		let proving_key = keygen(&params, random_circuit).unwrap();

		let manager = Manager::new(params, proving_key);
		let arc_manager = Arc::new(Mutex::new(manager));

		let req = Request::get(Uri::from_static("http://localhost:3000/non_existing_route"))
			.body(Body::default())
			.unwrap();

		let res = handle_request(req, arc_manager).await.unwrap();
		assert_eq!(*res.body(), ResponseBody::InvalidRequest.to_string());
	}

	#[tokio::test]
	async fn should_query_score() {
		let mut rng = thread_rng();
		let params = ParamsKZG::new(14);
		let random_circuit =
			EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::random(&mut rng);
		let proving_key = keygen(&params, random_circuit).unwrap();

		let mut manager = Manager::new(params, proving_key);
		manager.generate_initial_attestations();
		let epoch = Epoch(0);
		manager.calculate_proofs(epoch).unwrap();
		let real_proof = manager.get_proof(epoch).unwrap();
		let arc_manager = Arc::new(Mutex::new(manager));

		let req = Request::get(Uri::from_static(
			"http://localhost:3000/score?pk=92tZdMN2SjXbT9byaHHt7hDDNXUphjwRt5UB3LDbgSmR&epoch=0",
		))
		.body(Body::default())
		.unwrap();

		let res = handle_request(req, arc_manager).await.unwrap();
		assert_eq!(*res.body(), to_string(&real_proof).unwrap());
	}

	#[tokio::test]
	async fn should_fail_attestation_add_with_invalid_data() {
		let mut rng = thread_rng();
		let params = ParamsKZG::new(14);
		let random_circuit =
			EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::random(&mut rng);
		let proving_key = keygen(&params, random_circuit).unwrap();

		let manager = Manager::new(params, proving_key);
		let arc_manager = Arc::new(Mutex::new(manager));

		let (sks, pks) = keyset_from_raw(FIXED_SET);
		let score = Scalar::from_u128(INITIAL_SCORE / NUM_NEIGHBOURS as u128);
		let scores = vec![vec![score; NUM_NEIGHBOURS]];
		let (_, message_hash) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(pks.clone(), scores.clone());
		let sig = sign(&sks[0], &pks[0], message_hash[0]);
		let attestation = Attestation::new(sig, pks[0].clone(), pks, scores[0].clone());
		let attestation_data: AttestationData = attestation.into();
		let mut attestation_bytes = to_vec(&attestation_data).unwrap();
		// Remove some bytes
		attestation_bytes.drain(..10);

		let req = Request::post(Uri::from_static("http://localhost:3000/attestation"))
			.body(Body::from(attestation_bytes))
			.unwrap();

		let res = handle_request(req, arc_manager).await.unwrap();
		assert_eq!(*res.body(), ResponseBody::InvalidRequest.to_string());
	}

	#[tokio::test]
	async fn should_add_attestation() {
		let mut rng = thread_rng();
		let params = ParamsKZG::new(14);
		let random_circuit =
			EigenTrust::<NUM_NEIGHBOURS, NUM_ITER, INITIAL_SCORE, SCALE>::random(&mut rng);
		let proving_key = keygen(&params, random_circuit).unwrap();

		let manager = Manager::new(params, proving_key);
		let arc_manager = Arc::new(Mutex::new(manager));

		let (sks, pks) = keyset_from_raw(FIXED_SET);
		let score = Scalar::from_u128(INITIAL_SCORE / NUM_NEIGHBOURS as u128);
		let scores = vec![vec![score; NUM_NEIGHBOURS]];
		let (_, message_hash) =
			calculate_message_hash::<NUM_NEIGHBOURS, 1>(pks.clone(), scores.clone());
		let sig = sign(&sks[0], &pks[0], message_hash[0]);
		let attestation = Attestation::new(sig, pks[0].clone(), pks, scores[0].clone());
		let attestation_data: AttestationData = attestation.into();
		let attestation_bytes = to_vec(&attestation_data).unwrap();

		let req = Request::post(Uri::from_static("http://localhost:3000/attestation"))
			.body(Body::from(attestation_bytes))
			.unwrap();

		let res = handle_request(req, arc_manager).await.unwrap();
		assert_eq!(*res.body(), ResponseBody::AttestationAddSuccess.to_string());
	}
}
