#![feature(async_closure)]

use ethers::{
	contract::Contract,
	providers::StreamExt,
	solc::utils::read_json_file,
	types::{Address, ValueOrArray},
};
use hyper::{server::conn::Http, service::service_fn, Body, Method, Request, Response};
use once_cell::sync::Lazy;
use rand::thread_rng;
use serde::Deserialize;
use serde_json::to_string;
use std::{
	collections::HashMap,
	mem::drop,
	net::SocketAddr,
	path::Path,
	sync::{Arc, Mutex},
};
use tokio::{
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
	ethereum::{setup_client, AttestationCreatedFilter},
	manager::{
		attestation::{Attestation, AttestationData},
		Manager, Proof, INITIAL_SCORE, NUM_ITER, NUM_NEIGHBOURS, SCALE,
	},
};

#[derive(Deserialize)]
struct ProtocolConfig {
	epoch_interval: u64,
	endpoint: ([u8; 4], u16),
	ethereum_node_url: String,
	as_contract_address: String,
}

const BAD_REQUEST: u16 = 400;
const NOT_FOUND: u16 = 404;
const INTERNAL_SERVER_ERROR: u16 = 500;

#[derive(Debug)]
enum ResponseBody {
	Score(Proof),
	LockError,
	InvalidQuery,
	InvalidRequest,
}

impl ToString for ResponseBody {
	fn to_string(&self) -> String {
		match self {
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

	const NN: usize = NUM_NEIGHBOURS;
	const NI: usize = NUM_ITER;
	const IS: u128 = INITIAL_SCORE;
	const S: u128 = SCALE;
	let random_circuit = EigenTrust::<NN, NI, IS, S>::random(&mut rng);
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
		_ => {
			return Ok(Response::builder()
				.status(NOT_FOUND)
				.body(ResponseBody::InvalidRequest.to_string())
				.unwrap())
		},
	}
}

#[tokio::main]
async fn main() -> Result<(), EigenError> {
	let source = Path::new(&env!("CARGO_MANIFEST_DIR")).join("data/protocol-config.json");
	let config: ProtocolConfig = read_json_file(source).unwrap();

	let addr: SocketAddr = config.endpoint.into();
	let listener = TcpListener::bind(addr).await.map_err(|_| EigenError::ListenError)?;
	println!("Listening on https://{}", addr);

	let interval = Duration::from_secs(config.epoch_interval);
	let mut inner_interval = time::interval(interval);
	inner_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

	let mng_store = Arc::clone(&MANAGER_STORE);
	let mut manager = mng_store.lock().unwrap();
	manager.generate_initial_attestations();
	drop(manager);

	let client = setup_client(&config.ethereum_node_url);
	let att_created_event = Contract::event_of_type::<AttestationCreatedFilter>(&client);
	let att_created_event = att_created_event.from_block(0).address(ValueOrArray::Value(
		config.as_contract_address.parse::<Address>().unwrap(),
	));
	let mut event_stream = att_created_event.stream().await.unwrap();

	loop {
		select! {
			listen_res = listener.accept() => {
				let (stream, _) = listen_res.map_err(|_| EigenError::ConnectionError)?;
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
			_tick_res = inner_interval.tick() => {
				let epoch = Epoch::current_epoch(config.epoch_interval);
				let manager = mng_store.lock();

				if manager.is_err() {
					let e = manager.err();
					println!("error: {:?}", e);
				} else {
					let mut manager = manager.unwrap();
					manager.calculate_proofs(epoch).unwrap();
				}
			}
			event_res = event_stream.next() => {
				 if let Some(Ok(att_created)) = event_res {
					let AttestationCreatedFilter { val, .. } = att_created;

					let att_data = AttestationData::from_bytes(val.to_vec());
					let att = Attestation::from(att_data.clone());

					let mng_store = Arc::clone(&MANAGER_STORE);
					let mut manager = mng_store.lock().unwrap();
					manager.add_attestation(att).unwrap();
				}
			}
		};
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use hyper::Uri;

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
}
