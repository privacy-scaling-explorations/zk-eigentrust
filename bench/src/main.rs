use env_logger::Builder;
use futures::future::join_all;
use std::str::FromStr;

use csv::Reader as CsvReader;
use eigen_trust_circuit::{
	halo2wrong::curves::bn256::Bn256,
	poseidon::params::bn254_5x5::Params5x5Bn254,
	utils::{keygen, random_circuit, read_params},
};
use eigen_trust_protocol::{
	constants::{MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS},
	keypair_from_sk_bytes, LevelFilter, Multiaddr, Node, Peer,
};
use rand::{thread_rng, Rng};
use serde::Deserialize;
use std::env::current_dir;

const NUM_CONNECTIONS: usize = 4;

#[derive(Debug, Deserialize)]
struct Keypair {
	secret_key: String,
	public_key: String,
}

pub fn init_logger() {
	let mut builder = Builder::from_default_env();
	builder.filter(Some("eigen_trust"), LevelFilter::Debug).format_timestamp(None).init();
}

#[tokio::main]
async fn main() {
	init_logger();

	let mut local_keys = Vec::new();
	let mut local_addresses = Vec::new();
	let mut bootstrap_nodes = Vec::new();
	let starting_port = 58400;

	let current_path = current_dir().unwrap();
	let path_to_data = format!("{}/../data", current_path.display());
	let mut rdr = CsvReader::from_path(format!("{}/bootstrap-nodes.csv", path_to_data)).unwrap();
	let mut keys = Vec::new();
	for result in rdr.deserialize() {
		let record: Keypair = result.expect("Failed to Keypair");
		keys.push(record.secret_key);
	}

	for (i, key) in keys.iter().enumerate() {
		let sk_bytes = bs58::decode(key).into_vec().unwrap();
		let local_key = keypair_from_sk_bytes(sk_bytes).unwrap();
		let peer_id = local_key.public().to_peer_id();
		let addr = format!("/ip4/127.0.0.1/tcp/{}", starting_port + i);
		let local_address = Multiaddr::from_str(&addr).unwrap();

		local_keys.push(local_key);
		local_addresses.push(local_address.clone());
		bootstrap_nodes.push((peer_id, local_address));
	}

	let params = read_params::<Bn256>(&format!("{}/params-9.bin", path_to_data));
	let rng = &mut thread_rng();
	let random_circuit =
		random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params5x5Bn254>(rng);
	let pk = keygen(&params, &random_circuit).unwrap();

	let mut tasks = Vec::new();
	for i in 0..NUM_CONNECTIONS {
		let la_clone = local_addresses.clone();
		let local_key = local_keys[i].clone();
		let local_address = la_clone[i].clone();
		let bootstrap_nodes = bootstrap_nodes.clone();
		let params = params.clone();
		let pk = pk.clone();

		let join_handle = tokio::spawn(async move {
			let neighbor_addr = la_clone.clone();
			let mut peer = Peer::new(local_key.clone(), params, pk).unwrap();
			for (peer_id, ..) in bootstrap_nodes {
				let random_score: u32 = rand::thread_rng().gen_range(0..100);
				peer.set_score(peer_id, random_score);
			}

			let mut node = Node::new(local_key, local_address, peer).unwrap();
			for j in 0..NUM_CONNECTIONS {
				node.dial_neighbor(neighbor_addr[j].clone());
			}
			node.main_loop(1).await;
		});
		tasks.push(join_handle);
	}

	let _ = join_all(tasks).await;
	println!("Done");
}
