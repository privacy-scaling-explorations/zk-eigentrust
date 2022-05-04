#![allow(clippy::tabs_in_doc_comments)]
#![deny(
	future_incompatible,
	nonstandard_style,
	deprecated,
	unreachable_code,
	unreachable_patterns,
	absolute_paths_not_starting_with_crate,
	unsafe_code,
	clippy::unwrap_used,
	clippy::panic,
	clippy::unnecessary_cast,
	clippy::cast_lossless,
	clippy::cast_possible_truncation,
	clippy::cast_possible_wrap,
	clippy::cast_precision_loss,
	clippy::cast_sign_loss
)]
#![warn(trivial_casts)]
#![forbid(unsafe_code)]

use clap::Parser;
use env_logger::Builder;
use libp2p::{identity::Keypair, Multiaddr, PeerId};
use log::LevelFilter;
use std::str::FromStr;

mod node;
mod protocol;

use node::{setup_node, start_loop};

const BOOTSTRAP_PEERS: [[&str; 2]; 2] = [
	[
		"/ip4/127.0.0.1/tcp/58584",
		"12D3KooWLyTCx9j2FMcsHe81RMoDfhXbdyyFgNGQMdcrnhShTvQh",
	],
	[
		"/ip4/127.0.0.1/tcp/58601",
		"12D3KooWKBKXsLwbmVBySEmbKayJzfWp3tPCKrnDCsmNy9prwjvy",
	],
];

const DEFAULT_ADDRESS: &str = "/ip4/0.0.0.0/tcp/0";
const NUM_NEIGHBOURS: u32 = 256;

#[derive(Parser, Debug)]
struct Args {
	#[clap(short, long)]
	key: Option<String>,
	#[clap(short, long)]
	address: Option<String>,
}

#[derive(Debug)]
pub enum EigenError {
	InvalidKeypair,
	InvalidAddress,
	InvalidPeerId,
	ListenFailed,
	DialError,
	MaxNeighboursReached,
	NeighbourNotFound,
}

pub struct Peer {
	neighbours: [Option<PeerId>; NUM_NEIGHBOURS as usize],
}

impl Peer {
	pub fn new() -> Self {
		Peer {
			neighbours: [None; NUM_NEIGHBOURS as usize],
		}
	}

	pub fn add_neighbour(&mut self, neighbour: PeerId) -> Result<(), EigenError> {
		let first_available = self.neighbours.iter().position(|n| n.is_none());
		if let Some(index) = first_available {
			self.neighbours[index] = Some(neighbour);
			return Ok(());
		}
		Err(EigenError::MaxNeighboursReached)
	}

	pub fn remove_neighbour(&mut self, neighbour: PeerId) -> Result<(), EigenError> {
		let index = self
			.neighbours
			.iter()
			.position(|n| n.map(|n| n == neighbour).unwrap_or(false));
		if let Some(index) = index {
			self.neighbours[index] = None;
			return Ok(());
		}
		Err(EigenError::NeighbourNotFound)
	}
}

pub fn init_logger() {
	let mut builder = Builder::from_default_env();

	builder
		.filter(None, LevelFilter::Info)
		.format_timestamp(None)
		.init();
}

#[async_std::main]
async fn main() -> Result<(), EigenError> {
	init_logger();

	let args = Args::parse();

	// Taking the keypair from the command line or generating a new one.
	let local_key = if let Some(key) = args.key {
		let decoded_key = bs58::decode(&key).into_vec().map_err(|e| {
			log::debug!("bs58::decode {:?}", e);
			EigenError::InvalidKeypair
		})?;
		Keypair::from_protobuf_encoding(&decoded_key).map_err(|e| {
			log::debug!("Keypair::from_protobuf_encoding {:?}", e);
			EigenError::InvalidKeypair
		})?
	} else {
		Keypair::generate_ed25519()
	};

	// Taking the address from the command line arguments or the default one.
	let local_address = if let Some(addr) = args.address {
		Multiaddr::from_str(&addr).map_err(|e| {
			log::debug!("Multiaddr::from_str {:?}", e);
			EigenError::InvalidAddress
		})?
	} else {
		Multiaddr::from_str(&DEFAULT_ADDRESS).map_err(|e| {
			log::debug!("Multiaddr::from_str {:?}", e);
			EigenError::InvalidAddress
		})?
	};

	let mut bootstrap_nodes = Vec::new();
	for info in BOOTSTRAP_PEERS.iter() {
		// We can also contact the address.
		let peer_addr = Multiaddr::from_str(info[0]).map_err(|e| {
			log::debug!("Multiaddr::from_str {:?}", e);
			EigenError::InvalidAddress
		})?;
		let peer_id = PeerId::from_str(info[1]).map_err(|e| {
			log::debug!("PeerId::from_str {:?}", e);
			EigenError::InvalidPeerId
		})?;

		bootstrap_nodes.push((peer_id, peer_addr));
	}

	let mut swarm = setup_node(local_key, local_address, bootstrap_nodes, NUM_NEIGHBOURS).await?;

	let mut peer = Peer::new();

	start_loop(&mut peer, &mut swarm).await;

	Ok(())
}
