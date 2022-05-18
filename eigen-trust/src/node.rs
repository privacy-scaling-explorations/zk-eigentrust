use crate::{
	epoch::Epoch,
	peer::Peer,
	protocol::{EigenTrustCodec, EigenTrustProtocol, Request, Response},
	EigenError,
};
use futures::StreamExt;
use libp2p::{
	core::upgrade::Version,
	identity::Keypair,
	noise::{Keypair as NoiseKeypair, NoiseConfig, X25519Spec},
	request_response::{
		ProtocolSupport, RequestResponse, RequestResponseConfig, RequestResponseEvent,
		RequestResponseMessage,
	},
	swarm::{ConnectionHandlerUpgrErr, ConnectionLimits, Swarm, SwarmBuilder, SwarmEvent},
	tcp::TcpConfig,
	yamux::YamuxConfig,
	Multiaddr, PeerId, Transport,
};
use std::{io::Error as IoError, iter::once, marker::PhantomData};
use tokio::{
	select,
	time::{self, Duration, Instant},
};

pub trait NodeConfig {
	const NUM_CONNECTIONS: usize;
	const INTERVAL: u64;
	const PRE_TRUST_WEIGHT: f64;
}

pub struct Node<C: NodeConfig> {
	swarm: Swarm<RequestResponse<EigenTrustCodec>>,
	peer: Peer,
	local_key: Keypair,
	bootstrap_nodes: Vec<(PeerId, Multiaddr, f64)>,
	_config: PhantomData<C>,
}

impl<C: NodeConfig> Node<C> {
	pub fn new(
		local_key: Keypair,
		local_address: Multiaddr,
		bootstrap_nodes: Vec<(PeerId, Multiaddr, f64)>,
	) -> Result<Self, EigenError> {
		let noise_keys = NoiseKeypair::<X25519Spec>::new()
			.into_authentic(&local_key)
			.map_err(|e| {
				log::error!("NoiseKeypair.into_authentic {}", e);
				EigenError::InvalidKeypair
			})?;

		let transport = TcpConfig::new()
			.nodelay(true)
			.upgrade(Version::V1)
			.authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
			.multiplex(YamuxConfig::default())
			// 30 years
			.timeout(Duration::from_secs(86400 * 365 * 30))
			.boxed();

		// Setting up the request/response protocol.
		let protocols = once((EigenTrustProtocol::new(), ProtocolSupport::Full));
		let cfg = RequestResponseConfig::default();
		let req_proto = RequestResponse::new(EigenTrustCodec, protocols, cfg);

		// Setting up the transport and swarm.
		let local_peer_id = PeerId::from(local_key.public());
		let num_connections =
			u32::try_from(C::NUM_CONNECTIONS).map_err(|_| EigenError::InvalidNumNeighbours)?;
		let connection_limits =
			ConnectionLimits::default().with_max_established_per_peer(Some(num_connections));

		let mut swarm = SwarmBuilder::new(transport, req_proto, local_peer_id)
			.connection_limits(connection_limits)
			.build();

		swarm.listen_on(local_address).map_err(|e| {
			log::debug!("swarm.listen_on {:?}", e);
			EigenError::ListenFailed
		})?;

		let pre_trust_score = bootstrap_nodes
			.iter()
			.find(|x| x.0 == local_peer_id)
			.map(|node| node.2)
			.unwrap_or(0.0);
		let peer = Peer::new(C::NUM_CONNECTIONS, pre_trust_score, C::PRE_TRUST_WEIGHT);

		Ok(Self {
			swarm,
			peer,
			local_key,
			bootstrap_nodes,
			_config: PhantomData,
		})
	}

	pub fn get_peer(&self) -> &Peer {
		&self.peer
	}

	pub fn get_peer_mut(&mut self) -> &mut Peer {
		&mut self.peer
	}

	pub fn get_swarm_mut(&mut self) -> &mut Swarm<RequestResponse<EigenTrustCodec>> {
		&mut self.swarm
	}

	pub fn handle_req_res_events(&mut self, event: RequestResponseEvent<Request, Response>) {
		use RequestResponseEvent::*;
		use RequestResponseMessage::{Request as Req, Response as Res};
		match event {
			Message {
				peer,
				message: Req {
					request, channel, ..
				},
			} => {
				let beh = self.swarm.behaviour_mut();
				self.peer.calculate_local_opinions(request.get_epoch());
				let opinion = self.peer.get_local_opinion(&(peer, request.get_epoch()));
				let response = Response::Success(opinion);
				let res = beh.send_response(channel, response);
				if let Err(e) = res {
					log::error!("Failed to send the response {:?}", e);
				}
			},
			Message {
				peer,
				message: Res { response, .. },
			} => {
				if let Response::Success(opinion) = response {
					self.peer
						.cache_neighbour_opinion((peer, opinion.get_epoch()), opinion);
				} else {
					log::error!("Received error response {:?}", response);
				}
			},
			OutboundFailure {
				peer, request_id, ..
			} => {
				log::error!("Outbound failure {:?} from {:?}", request_id, peer);
			},
			InboundFailure {
				peer, request_id, ..
			} => {
				log::error!("Inbound failure {:?} from {:?}", request_id, peer);
			},
			ResponseSent { peer, request_id } => {
				log::debug!("Response sent {:?} to {:?}", request_id, peer);
			},
		};
	}

	pub fn handle_swarm_events(
		&mut self,
		event: SwarmEvent<
			RequestResponseEvent<Request, Response>,
			ConnectionHandlerUpgrErr<IoError>,
		>,
	) {
		match event {
			SwarmEvent::NewListenAddr { address, .. } => log::info!("Listening on {:?}", address),
			SwarmEvent::Behaviour(req_res_event) => self.handle_req_res_events(req_res_event),
			// When we connect to a peer, we automatically add him as a neighbour.
			SwarmEvent::ConnectionEstablished { peer_id, .. } => {
				let res = self.peer.add_neighbour(peer_id);
				if let Err(e) = res {
					log::error!("Failed to add neighbour {:?}", e);
				}
				log::info!("Connection established with {:?}", peer_id);
			},
			// When we disconnect from a peer, we automatically remove him from the neighbours list.
			SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
				self.peer.remove_neighbour(peer_id);
				log::info!("Connection closed with {:?} ({:?})", peer_id, cause);
			},
			SwarmEvent::Dialing(peer_id) => log::info!("Dialing {:?}", peer_id),
			e => log::debug!("{:?}", e),
		}
	}

	pub fn dial_neighbour(&mut self, addr: Multiaddr) {
		let res = self.swarm.dial(addr).map_err(|_| EigenError::DialError);
		log::debug!("swarm.dial {:?}", res);
	}

	pub fn dial_bootstrap_nodes(&mut self) {
		// We want to connect to all bootstrap nodes.
		let local_peer_id = self.local_key.public().to_peer_id();
		for (peer_id, peer_addr, _) in self.bootstrap_nodes.iter_mut() {
			if peer_id == &local_peer_id {
				continue;
			}

			let res = self
				.swarm
				.dial(peer_addr.clone())
				.map_err(|_| EigenError::DialError);
			log::debug!("swarm.dial {:?}", res);
		}
	}

	pub fn send_epoch_requests(&mut self, epoch: Epoch) {
		for peer_id in self.peer.neighbours() {
			let beh = self.swarm.behaviour_mut();

			let request = Request::new(epoch);
			beh.send_request(&peer_id, request);
		}
	}

	pub async fn develop_loop(mut self, num_intervals: u32) -> Result<(), EigenError> {
		self.dial_bootstrap_nodes();

		let now = Instant::now();
		let secs_until_next_epoch = Epoch::secs_until_next_epoch(C::INTERVAL)?;
		let start = now + Duration::from_secs(secs_until_next_epoch);
		let period = Duration::from_secs(C::INTERVAL);

		let mut interval = time::interval_at(start, period);

		let mut count = 0;

		loop {
			select! {
				biased;
				_ = interval.tick() => {
					let current_epoch = Epoch::current_epoch(C::INTERVAL)?;
					let local_peer_id = self.local_key.public().to_peer_id();
					log::info!("Epoch started {:?} for peer {:?}", current_epoch, local_peer_id);
					self.send_epoch_requests(current_epoch);
					count += 1;
					if count >= num_intervals {
						break;
					}
				},
				event = self.swarm.select_next_some() => self.handle_swarm_events(event),
			}
		}

		Ok(())
	}

	pub async fn main_loop(mut self) -> Result<(), EigenError> {
		self.dial_bootstrap_nodes();

		let now = Instant::now();
		let secs_until_next_epoch = Epoch::secs_until_next_epoch(C::INTERVAL)?;
		let start = now + Duration::from_secs(secs_until_next_epoch);
		let period = Duration::from_secs(C::INTERVAL);

		let mut interval = time::interval_at(start, period);

		loop {
			select! {
				biased;
				_ = interval.tick() => {
					let current_epoch = Epoch::current_epoch(C::INTERVAL)?;
					self.send_epoch_requests(current_epoch);
				},
				event = self.swarm.select_next_some() => self.handle_swarm_events(event),
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::str::FromStr;

	struct TestConfig;
	impl NodeConfig for TestConfig {
		const INTERVAL: u64 = 10;
		const PRE_TRUST_WEIGHT: f64 = 0.5;
		const NUM_CONNECTIONS: usize = 1;
	}

	const PRE_TRUST_SCORE: f64 = 0.5;

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
			(peer_id1, local_address1.clone(), PRE_TRUST_SCORE),
			(peer_id2, local_address2.clone(), PRE_TRUST_SCORE),
		];

		let mut node1 = Node::<TestConfig>::new(
			local_key1,
			local_address1.clone(),
			bootstrap_nodes.clone(),
		)
		.unwrap();
		let mut node2 = Node::<TestConfig>::new(
			local_key2,
			local_address2,
			bootstrap_nodes,
		)
		.unwrap();

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
	async fn should_add_neighbours_on_bootstrap() {
		const ADDR_1: &str = "/ip4/127.0.0.1/tcp/56707";
		const ADDR_2: &str = "/ip4/127.0.0.1/tcp/58602";

		let local_key1 = Keypair::generate_ed25519();
		let peer_id1 = local_key1.public().to_peer_id();

		let local_key2 = Keypair::generate_ed25519();
		let peer_id2 = local_key2.public().to_peer_id();

		let local_address1 = Multiaddr::from_str(ADDR_1).unwrap();
		let local_address2 = Multiaddr::from_str(ADDR_2).unwrap();

		let bootstrap_nodes = vec![
			(peer_id1, local_address1.clone(), PRE_TRUST_SCORE),
			(peer_id2, local_address2.clone(), PRE_TRUST_SCORE),
		];

		let mut node1 = Node::<TestConfig>::new(
			local_key1,
			local_address1,
			bootstrap_nodes.clone(),
		)
		.unwrap();
		let mut node2 = Node::<TestConfig>::new(
			local_key2,
			local_address2,
			bootstrap_nodes,
		)
		.unwrap();

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

		let neighbours1: Vec<PeerId> = node1.get_peer().neighbours();
		let neighbours2: Vec<PeerId> = node2.get_peer().neighbours();
		let expected_neighbour1 = vec![peer_id2];
		let expected_neighbour2 = vec![peer_id1];
		assert_eq!(neighbours1, expected_neighbour1);
		assert_eq!(neighbours2, expected_neighbour2);

		// Disconnect from peer
		node2.get_swarm_mut().disconnect_peer_id(peer_id1).unwrap();

		// Two disconnect events
		for _ in 0..2 {
			select! {
				event2 = node2.get_swarm_mut().select_next_some() => node2.handle_swarm_events(event2),
				event1 = node1.get_swarm_mut().select_next_some() => node1.handle_swarm_events(event1),

			}
		}

		let neighbours2: Vec<PeerId> = node2.get_peer().neighbours();
		let neighbours1: Vec<PeerId> = node1.get_peer().neighbours();
		assert!(neighbours2.is_empty());
		assert!(neighbours1.is_empty());
	}

	#[tokio::test]
	async fn should_add_neighbours_on_dial() {
		const ADDR_1: &str = "/ip4/127.0.0.1/tcp/56717";
		const ADDR_2: &str = "/ip4/127.0.0.1/tcp/58622";

		let local_key1 = Keypair::generate_ed25519();
		let peer_id1 = local_key1.public().to_peer_id();

		let local_key2 = Keypair::generate_ed25519();
		let peer_id2 = local_key2.public().to_peer_id();

		let local_address1 = Multiaddr::from_str(ADDR_1).unwrap();
		let local_address2 = Multiaddr::from_str(ADDR_2).unwrap();

		let mut node1 = Node::<TestConfig>::new(
			local_key1,
			local_address1,
			Vec::new(),
		)
		.unwrap();
		let mut node2 = Node::<TestConfig>::new(
			local_key2,
			local_address2.clone(),
			Vec::new(),
		)
		.unwrap();

		node1.dial_neighbour(local_address2);

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

		let neighbours1: Vec<PeerId> = node1.get_peer().neighbours();
		let neighbours2: Vec<PeerId> = node2.get_peer().neighbours();
		let expected_neighbour1 = vec![peer_id2];
		let expected_neighbour2 = vec![peer_id1];
		assert_eq!(neighbours1, expected_neighbour1);
		assert_eq!(neighbours2, expected_neighbour2);

		// Disconnect from peer
		node2.get_swarm_mut().disconnect_peer_id(peer_id1).unwrap();

		// Two disconnect events
		for _ in 0..2 {
			select! {
				event2 = node2.get_swarm_mut().select_next_some() => node2.handle_swarm_events(event2),
				event1 = node1.get_swarm_mut().select_next_some() => node1.handle_swarm_events(event1),

			}
		}

		let neighbours2: Vec<PeerId> = node2.get_peer().neighbours();
		let neighbours1: Vec<PeerId> = node1.get_peer().neighbours();
		assert!(neighbours2.is_empty());
		assert!(neighbours1.is_empty());
	}

	#[tokio::test]
	async fn should_handle_request_for_opinion() {
		const ADDR_1: &str = "/ip4/127.0.0.1/tcp/56708";
		const ADDR_2: &str = "/ip4/127.0.0.1/tcp/58603";

		let local_key1 = Keypair::generate_ed25519();
		let peer_id1 = local_key1.public().to_peer_id();

		let local_key2 = Keypair::generate_ed25519();
		let peer_id2 = local_key2.public().to_peer_id();

		let local_address1 = Multiaddr::from_str(ADDR_1).unwrap();
		let local_address2 = Multiaddr::from_str(ADDR_2).unwrap();

		let bootstrap_nodes = vec![
			(peer_id1, local_address1.clone(), PRE_TRUST_SCORE),
			(peer_id2, local_address2.clone(), PRE_TRUST_SCORE),
		];

		let mut node1 = Node::<TestConfig>::new(
			local_key1,
			local_address1,
			bootstrap_nodes.clone(),
		)
		.unwrap();
		let mut node2 = Node::<TestConfig>::new(
			local_key2,
			local_address2,
			bootstrap_nodes,
		)
		.unwrap();

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

		let peer1 = node1.get_peer_mut();
		let peer2 = node2.get_peer_mut();

		let current_epoch = Epoch(0);
		let next_epoch = current_epoch.next();

		peer1.set_score(peer_id2, 5);
		peer2.set_score(peer_id1, 5);

		peer1.calculate_local_opinions(current_epoch);
		peer2.calculate_local_opinions(current_epoch);

		node1.send_epoch_requests(next_epoch);
		node2.send_epoch_requests(next_epoch);

		// Expecting 2 request messages
		// Expecting 2 response sent messages
		// Expecting 2 response received messages
		// Total of 6 messages
		for _ in 0..6 {
			select! {
				event1 = node1.get_swarm_mut().select_next_some() => {
					if let SwarmEvent::Behaviour(req_res) = event1 {
						node1.handle_req_res_events(req_res);
					}
				},
				event2 = node2.get_swarm_mut().select_next_some() => {
					if let SwarmEvent::Behaviour(req_res) = event2 {
						node2.handle_req_res_events(req_res);
					}
				},
			}
		}

		let peer1 = node1.get_peer();
		let peer2 = node2.get_peer();
		let peer1_neighbor_opinion = peer1.get_neighbour_opinion(&(peer_id2, next_epoch));
		let peer2_neighbor_opinion = peer2.get_neighbour_opinion(&(peer_id1, next_epoch));

		assert_eq!(peer1_neighbor_opinion.get_epoch(), next_epoch);
		assert_eq!(peer1_neighbor_opinion.get_local_trust_score(), 1.0);
		assert_eq!(peer1_neighbor_opinion.get_global_trust_score(), 0.25);
		assert_eq!(peer1_neighbor_opinion.get_product(), 0.25);

		assert_eq!(peer2_neighbor_opinion.get_epoch(), next_epoch);
		assert_eq!(peer2_neighbor_opinion.get_local_trust_score(), 1.0);
		assert_eq!(peer2_neighbor_opinion.get_global_trust_score(), 0.25);
		assert_eq!(peer2_neighbor_opinion.get_product(), 0.25);

		let peer1_global_score = peer1.calculate_global_trust_score(next_epoch);
		let peer2_global_score = peer1.calculate_global_trust_score(next_epoch);

		let peer_gs = (1. - TestConfig::PRE_TRUST_WEIGHT) * 0.25 + TestConfig::PRE_TRUST_WEIGHT * PRE_TRUST_SCORE;
		assert_eq!(peer1_global_score, peer_gs);
		assert_eq!(peer2_global_score, peer_gs);
	}
}
