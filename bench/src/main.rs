use std::str::FromStr;
use futures::future::join_all;
use env_logger::Builder;

use eigen_trust::{Keypair, Multiaddr, LevelFilter, Node, NodeConfig};

struct BenchConfig;
impl NodeConfig for BenchConfig {
	const NUM_CONNECTIONS: usize = 12;
	const INTERVAL: u64 = 2;
	const PRE_TRUST_WEIGHT: f64 = 0.2;
}

pub fn init_logger() {
	let mut builder = Builder::from_default_env();

	builder
		.filter(None, LevelFilter::Info)
		.format_timestamp(None)
		.init();
}

#[tokio::main]
async fn main() {
	init_logger();

	let mut local_keys = Vec::new();
	let mut local_addresses = Vec::new();
	let mut bootstrap_nodes = Vec::new();
	let starting_port = 58400;

	for i in 0..(BenchConfig::NUM_CONNECTIONS + 1) {
		let local_key = Keypair::generate_ed25519();
		let peer_id = local_key.public().to_peer_id();
		let addr = format!("/ip4/127.0.0.1/tcp/{}", starting_port + i);
		let local_address = Multiaddr::from_str(&addr).unwrap();

		local_keys.push(local_key);
		local_addresses.push(local_address.clone());
		bootstrap_nodes.push((peer_id, local_address, 0.5));
	}

	let mut tasks = Vec::new();
	for i in 0..(BenchConfig::NUM_CONNECTIONS + 1) {
		let local_key = local_keys[i].clone();
		let local_address = local_addresses[i].clone();
		let bootstrap_nodes = bootstrap_nodes.clone();

		let join_handle = tokio::spawn(async move {
			let mut node = Node::<BenchConfig>::new(
				local_key,
				local_address,
				bootstrap_nodes.clone(),
			).unwrap();

			let peer = node.get_peer_mut();
			for (peer_id, _, _) in bootstrap_nodes {
				peer.set_score(peer_id, 5);
			}

			node.develop_loop(10).await.unwrap();
		});
		tasks.push(join_handle);
	}

	let _ = join_all(tasks).await.iter().map(|r| r.as_ref().unwrap()).collect::<Vec<_>>();
	println!("Done");
}
