//! The module for the node setup, running the main loop, and handling network
//! events.

use crate::{epoch::Epoch, peer::Peer, protocol::EigenTrustBehaviour, EigenError};
use futures::StreamExt;
use libp2p::{
	core::{either::EitherError, upgrade::Version},
	identity::Keypair,
	noise::{Keypair as NoiseKeypair, NoiseConfig, X25519Spec},
	swarm::{ConnectionHandlerUpgrErr, Swarm, SwarmBuilder, SwarmEvent},
	tcp::TcpConfig,
	yamux::YamuxConfig,
	Multiaddr, PeerId, Transport,
};
use std::io::Error as IoError;
use tokio::{
	select,
	time::{self, Duration, Instant},
};

/// The Node struct.
pub struct Node {
	/// Swarm object.
	swarm: Swarm<EigenTrustBehaviour>,
	/// Local address.
	local_address: Multiaddr,
	/// Bootstrap nodes.
	bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
	interval: Duration,
}

impl Node {
	/// Create a new node, given the local keypair, local address, and bootstrap
	/// nodes.
	pub fn new(
		local_key: Keypair,
		local_address: Multiaddr,
		bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
		interval_secs: u64,
	) -> Result<Self, EigenError> {
		let noise_keys = NoiseKeypair::<X25519Spec>::new()
			.into_authentic(&local_key)
			.map_err(|e| {
				log::error!("NoiseKeypair.into_authentic {}", e);
				EigenError::InvalidKeypair
			})?;

		// 30 years in seconds
		// Basically, we want connections to be open for a long time.
		let connection_duration = Duration::from_secs(86400 * 365 * 30);
		let interval_duration = Duration::from_secs(interval_secs);
		let transport = TcpConfig::new()
			.nodelay(true)
			.upgrade(Version::V1)
			.authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
			.multiplex(YamuxConfig::default())
			.timeout(connection_duration)
			.boxed();

		let peer = Peer::new(local_key.clone());
		let beh = EigenTrustBehaviour::new(
			connection_duration,
			interval_duration,
			local_key.public(),
			peer,
		);

		// Setting up the transport and swarm.
		let local_peer_id = PeerId::from(local_key.public());
		let mut swarm = SwarmBuilder::new(transport, beh, local_peer_id).build();

		swarm.listen_on(local_address.clone()).map_err(|e| {
			log::debug!("swarm.listen_on {:?}", e);
			EigenError::ListenFailed
		})?;

		Ok(Self {
			swarm,
			local_address,
			bootstrap_nodes,
			interval: interval_duration,
		})
	}

	/// Get the mutable swarm.
	pub fn get_swarm_mut(&mut self) -> &mut Swarm<EigenTrustBehaviour> {
		&mut self.swarm
	}

	/// Get the swarm.
	pub fn get_swarm(&self) -> &Swarm<EigenTrustBehaviour> {
		&self.swarm
	}

	/// A method for handling the swarm events.
	pub fn handle_swarm_events(
		&mut self,
		event: SwarmEvent<(), EitherError<ConnectionHandlerUpgrErr<IoError>, std::io::Error>>,
	) {
		match event {
			SwarmEvent::NewListenAddr { address, .. } => log::info!("Listening on {:?}", address),
			// When we connect to a peer, we automatically add him as a neighbor.
			SwarmEvent::ConnectionEstablished { peer_id, .. } => {
				let res = self
					.swarm
					.behaviour_mut()
					.get_peer_mut()
					.add_neighbor(peer_id);
				if let Err(e) = res {
					log::error!("Failed to add neighbor {:?}", e);
				}
				log::info!("Connection established with {:?}", peer_id);
			},
			// When we disconnect from a peer, we automatically remove him from the neighbors list.
			SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
				self.swarm
					.behaviour_mut()
					.get_peer_mut()
					.remove_neighbor(peer_id);
				log::info!("Connection closed with {:?} ({:?})", peer_id, cause);
			},
			SwarmEvent::Dialing(peer_id) => log::info!("Dialing {:?}", peer_id),
			e => log::debug!("{:?}", e),
		}
	}

	/// Dial the neighbor directly.
	pub fn dial_neighbor(&mut self, addr: Multiaddr) {
		let res = self.swarm.dial(addr).map_err(|_| EigenError::DialError);
		log::debug!("swarm.dial {:?}", res);
	}

	/// Dial pre-configured bootstrap nodes.
	pub fn dial_bootstrap_nodes(&mut self) {
		// We want to connect to all bootstrap nodes.
		for (_, peer_addr) in self.bootstrap_nodes.iter_mut() {
			if self.local_address == *peer_addr {
				continue;
			}
			let res = self
				.swarm
				.dial(peer_addr.clone())
				.map_err(|_| EigenError::DialError);
			log::debug!("swarm.dial {:?}", res);
		}
	}

	/// Start the main loop of the program. This function has two main tasks:
	/// - To start an interval timer for sending the request for opinions.
	/// - To handle the swarm + request/response events.
	/// The amount of intervals/epochs is determined by the `interval_limit`
	/// parameter.
	pub async fn main_loop(mut self, interval_limit: Option<u32>) -> Result<(), EigenError> {
		self.dial_bootstrap_nodes();

		let now = Instant::now();
		let secs_until_next_epoch = Epoch::secs_until_next_epoch(self.interval.as_secs())?;
		// Figure out when the next epoch will start.
		let start = now + Duration::from_secs(secs_until_next_epoch);

		// Setup the interval timer.
		let mut interval = time::interval_at(start, self.interval);

		// Count the number of epochs passed
		let mut count = 0;

		loop {
			select! {
				biased;
				// The interval timer tick. This is where we request opinions from the neighbors.
				_ = interval.tick() => {
					let current_epoch = Epoch::current_epoch(self.interval.as_secs())?;

					let beh = self.swarm.behaviour_mut();
					// Log out the global trust score for the previous epoch.
					let score = beh.global_trust_score_at(current_epoch.previous());
					log::info!("{:?} finished, score: {}", current_epoch.previous(), score);

					// Send the request for opinions to all neighbors.
					beh.send_epoch_requests(current_epoch);

					// Increment the epoch counter, break out of the loop if we reached the limit
					if let Some(num) = interval_limit {
						count += 1;
						if count >= num {
							break;
						}
					}
				},
				// The swarm event.
				event = self.swarm.select_next_some() => self.handle_swarm_events(event),
			}
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::str::FromStr;

	const INTERVAL: u64 = 10;

	#[tokio::test]
	async fn should_emit_connection_event_on_bootstrap() {
		const ADDR_1: &str = "/ip4/127.0.0.1/tcp/56706";
		const ADDR_2: &str = "/ip4/127.0.0.1/tcp/58601";

		let local_key1 = Keypair::generate_ed25519();
		let peer_id1 = local_key1.public().to_peer_id();

		let local_key2 = Keypair::generate_ed25519();
		let peer_id2 = local_key2.public().to_peer_id();

		let local_address1 = Multiaddr::from_str(ADDR_1).unwrap();
		let local_address2 = Multiaddr::from_str(ADDR_2).unwrap();

		let bootstrap_nodes = vec![
			(peer_id1, local_address1.clone()),
			(peer_id2, local_address2.clone()),
		];

		let mut node1 = Node::new(
			local_key1,
			local_address1.clone(),
			bootstrap_nodes.clone(),
			INTERVAL,
		)
		.unwrap();
		let mut node2 = Node::new(local_key2, local_address2, bootstrap_nodes, INTERVAL).unwrap();

		node1.dial_bootstrap_nodes();

		// For node 2
		// 1. New listen addr
		// 2. Incoming connection
		// 3. Connection established
		// For node 1
		// 1. New listen addr
		// 2. Connection established
		for _ in 0..5 {
			select! {
				event2 = node2.get_swarm_mut().select_next_some() => {
					if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event2 {
						assert_eq!(peer_id, peer_id1);
					}
				},
				event1 = node1.get_swarm_mut().select_next_some() => {
					if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event1 {
						assert_eq!(peer_id, peer_id2);
					}
				},

			}
		}
	}

	#[tokio::test]
	async fn should_add_neighbors_on_bootstrap() {
		const ADDR_1: &str = "/ip4/127.0.0.1/tcp/56707";
		const ADDR_2: &str = "/ip4/127.0.0.1/tcp/58602";

		let local_key1 = Keypair::generate_ed25519();
		let peer_id1 = local_key1.public().to_peer_id();

		let local_key2 = Keypair::generate_ed25519();
		let peer_id2 = local_key2.public().to_peer_id();

		let local_address1 = Multiaddr::from_str(ADDR_1).unwrap();
		let local_address2 = Multiaddr::from_str(ADDR_2).unwrap();

		let bootstrap_nodes = vec![
			(peer_id1, local_address1.clone()),
			(peer_id2, local_address2.clone()),
		];

		let mut node1 = Node::new(
			local_key1,
			local_address1,
			bootstrap_nodes.clone(),
			INTERVAL,
		)
		.unwrap();
		let mut node2 = Node::new(local_key2, local_address2, bootstrap_nodes, INTERVAL).unwrap();

		node1.dial_bootstrap_nodes();

		// For node 2
		// 1. New listen addr
		// 2. Incoming connection
		// 3. Connection established
		// For node 1
		// 1. New listen addr
		// 2. Connection established
		for _ in 0..5 {
			select! {
				event2 = node2.get_swarm_mut().select_next_some() => node2.handle_swarm_events(event2),
				event1 = node1.get_swarm_mut().select_next_some() => node1.handle_swarm_events(event1),

			}
		}

		let neighbors1: Vec<PeerId> = node1.get_swarm().behaviour().get_peer().neighbors();
		let neighbors2: Vec<PeerId> = node2.get_swarm().behaviour().get_peer().neighbors();
		let expected_neighbor1 = vec![peer_id2];
		let expected_neighbor2 = vec![peer_id1];
		assert_eq!(neighbors1, expected_neighbor1);
		assert_eq!(neighbors2, expected_neighbor2);

		// Disconnect from peer
		node2.get_swarm_mut().disconnect_peer_id(peer_id1).unwrap();

		// Two disconnect events
		for _ in 0..2 {
			select! {
				event2 = node2.get_swarm_mut().select_next_some() => node2.handle_swarm_events(event2),
				event1 = node1.get_swarm_mut().select_next_some() => node1.handle_swarm_events(event1),

			}
		}

		let neighbors2: Vec<PeerId> = node2.get_swarm().behaviour().get_peer().neighbors();
		let neighbors1: Vec<PeerId> = node1.get_swarm().behaviour().get_peer().neighbors();
		assert!(neighbors2.is_empty());
		assert!(neighbors1.is_empty());
	}

	#[tokio::test]
	async fn should_add_neighbors_on_dial() {
		const ADDR_1: &str = "/ip4/127.0.0.1/tcp/56717";
		const ADDR_2: &str = "/ip4/127.0.0.1/tcp/58622";

		let local_key1 = Keypair::generate_ed25519();
		let peer_id1 = local_key1.public().to_peer_id();

		let local_key2 = Keypair::generate_ed25519();
		let peer_id2 = local_key2.public().to_peer_id();

		let local_address1 = Multiaddr::from_str(ADDR_1).unwrap();
		let local_address2 = Multiaddr::from_str(ADDR_2).unwrap();

		let mut node1 = Node::new(local_key1, local_address1, Vec::new(), INTERVAL).unwrap();
		let mut node2 =
			Node::new(local_key2, local_address2.clone(), Vec::new(), INTERVAL).unwrap();

		node1.dial_neighbor(local_address2);

		// For node 2
		// 1. New listen addr
		// 2. Incoming connection
		// 3. Connection established
		// For node 1
		// 1. New listen addr
		// 2. Connection established
		for _ in 0..5 {
			select! {
				event2 = node2.get_swarm_mut().select_next_some() => node2.handle_swarm_events(event2),
				event1 = node1.get_swarm_mut().select_next_some() => node1.handle_swarm_events(event1),

			}
		}

		let neighbors1: Vec<PeerId> = node1.get_swarm().behaviour().get_peer().neighbors();
		let neighbors2: Vec<PeerId> = node2.get_swarm().behaviour().get_peer().neighbors();
		let expected_neighbor1 = vec![peer_id2];
		let expected_neighbor2 = vec![peer_id1];
		assert_eq!(neighbors1, expected_neighbor1);
		assert_eq!(neighbors2, expected_neighbor2);

		// Disconnect from peer
		node2.get_swarm_mut().disconnect_peer_id(peer_id1).unwrap();

		// Two disconnect events
		for _ in 0..2 {
			select! {
				event2 = node2.get_swarm_mut().select_next_some() => node2.handle_swarm_events(event2),
				event1 = node1.get_swarm_mut().select_next_some() => node1.handle_swarm_events(event1),

			}
		}

		let neighbors2: Vec<PeerId> = node2.get_swarm().behaviour().get_peer().neighbors();
		let neighbors1: Vec<PeerId> = node1.get_swarm().behaviour().get_peer().neighbors();
		assert!(neighbors2.is_empty());
		assert!(neighbors1.is_empty());
	}

	#[tokio::test]
	async fn should_run_main_loop() {
		const ADDR_1: &str = "/ip4/127.0.0.1/tcp/56728";
		const ADDR_2: &str = "/ip4/127.0.0.1/tcp/58623";

		let local_key1 = Keypair::generate_ed25519();
		let peer_id1 = local_key1.public().to_peer_id();

		let local_key2 = Keypair::generate_ed25519();
		let peer_id2 = local_key2.public().to_peer_id();

		let local_address1 = Multiaddr::from_str(ADDR_1).unwrap();
		let local_address2 = Multiaddr::from_str(ADDR_2).unwrap();

		let bootstrap_nodes = vec![
			(peer_id1, local_address1.clone()),
			(peer_id2, local_address2.clone()),
		];

		let mut node1 = Node::new(
			local_key1,
			local_address1,
			bootstrap_nodes.clone(),
			INTERVAL,
		)
		.unwrap();
		let node2 = Node::new(local_key2, local_address2, bootstrap_nodes, INTERVAL).unwrap();

		node1.dial_bootstrap_nodes();

		let join1 = tokio::spawn(async move { node1.main_loop(Some(1)).await });

		let join2 = tokio::spawn(async move { node2.main_loop(Some(1)).await });

		let (res1, res2) = tokio::join!(join1, join2);
		res1.unwrap().unwrap();
		res2.unwrap().unwrap();
	}
}
