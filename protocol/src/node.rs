//! The module for the node setup, running the main loop, and handling network
//! events.

use crate::{
	behaviour::{
		req_res::{Request, Response},
		EigenEvent, EigenTrustBehaviour,
	},
	constants::{EPOCH_INTERVAL, ITER_INTERVAL, NUM_ITERATIONS},
	epoch::Epoch,
	peer::Peer,
	utils::create_iter,
	EigenError,
};
use futures::{select_biased, stream, StreamExt};
use libp2p::{
	core::{either::EitherError, upgrade::Version},
	identify::IdentifyEvent,
	identity::Keypair,
	noise::{Keypair as NoiseKeypair, NoiseConfig, X25519Spec},
	request_response::{RequestResponseEvent, RequestResponseMessage},
	swarm::{ConnectionHandlerUpgrErr, Swarm, SwarmBuilder, SwarmEvent},
	tcp::TcpConfig,
	yamux::YamuxConfig,
	Multiaddr, PeerId, Transport,
};
use std::io::Error as IoError;
use tokio::time::{Duration, Instant};

/// The Node struct.
pub struct Node {
	/// Swarm object.
	pub(crate) swarm: Swarm<EigenTrustBehaviour>,
	pub(crate) peer: Peer,
}

impl Node {
	/// Create a new node, given the local keypair, local address, and bootstrap
	/// nodes.
	pub fn new(
		local_key: Keypair, local_address: Multiaddr, peer: Peer,
	) -> Result<Self, EigenError> {
		let noise_keys =
			NoiseKeypair::<X25519Spec>::new().into_authentic(&local_key).map_err(|e| {
				log::error!("NoiseKeypair.into_authentic {}", e);
				EigenError::InvalidKeypair
			})?;
		// 30 years in seconds
		// Basically, we want connections to be open for a long time.
		let connection_duration = Duration::from_secs(86400 * 365 * 30);
		let transport = TcpConfig::new()
			.nodelay(true)
			.upgrade(Version::V1)
			.authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
			.multiplex(YamuxConfig::default())
			.timeout(connection_duration)
			.boxed();

		let beh = EigenTrustBehaviour::new(connection_duration, local_key.public());
		// Setting up the transport and swarm.
		let local_peer_id = PeerId::from(local_key.public());
		let mut swarm = SwarmBuilder::new(transport, beh, local_peer_id).build();

		swarm.listen_on(local_address).map_err(|e| {
			log::debug!("swarm.listen_on {:?}", e);
			EigenError::ListenFailed
		})?;

		Ok(Self { swarm, peer })
	}

	/// Handle the request response event.
	fn handle_req_res_events(&mut self, event: RequestResponseEvent<Request, Response>) {
		use RequestResponseEvent::*;
		use RequestResponseMessage::{Request as Req, Response as Res};
		match event {
			Message { peer, message: Req { request: Request::Ivp(ivp), channel, .. } } => {
				println!("{:?}", (peer, ivp.epoch, ivp.iter));
				// Cache neighbours Ivp
				let ivp_res =
					self.peer.cache_neighbor_ivp((peer, ivp.epoch, ivp.iter), ivp.clone());
				let response = match ivp_res {
					Err(err) => Response::InternalError(err),
					Ok(()) => Response::IvpSuccess,
				};
				let res = self.swarm.behaviour_mut().send_response(channel, response);
				if let Err(e) = res {
					log::error!("Failed to send the response {:?}", e);
				}
			},
			Message { peer, message: Res { response: Response::IvpSuccess, .. } } => {
				// Our Ivp proof was valid
				log::debug!("Ivp request successfuly recieved by: {:?}.", peer);
			},
			Message { peer, message: Req { request: Request::Identify(pub_key), channel, .. } } => {
				self.peer.identify_neighbor(peer, pub_key);
				let response = Response::Identify(self.peer.pubkey.clone());
				let res = self.swarm.behaviour_mut().send_response(channel, response);
				if let Err(e) = res {
					log::error!("Failed to send the response {:?}", e);
				}
			},
			Message { peer, message: Res { response: Response::Identify(pub_key), .. } } => {
				self.peer.identify_neighbor(peer, pub_key);
			},
			Message { message: Res { response, .. }, .. } => {
				log::error!("Received error response {:?}", response)
			},
			OutboundFailure { peer, request_id, error } => {
				log::error!("Outbound failure {:?} from {:?}: {:?}", request_id, peer, error);
			},
			InboundFailure { peer, request_id, error } => {
				log::error!("Inbound failure {:?} from {:?}: {:?}", request_id, peer, error);
			},
			ResponseSent { peer, request_id } => {
				log::debug!("Response sent {:?} to {:?}", request_id, peer);
			},
		};
	}

	/// Handle the identify protocol events.
	fn handle_identify_events(&mut self, event: IdentifyEvent) {
		match event {
			IdentifyEvent::Received { peer_id, info } => {
				self.peer.identify_neighbor_native(peer_id, info.public_key);
				log::info!("Neighbor identified {:?}", peer_id);
			},
			IdentifyEvent::Sent { peer_id } => {
				log::debug!("Identify request sent to {:?}", peer_id);
			},
			IdentifyEvent::Pushed { peer_id } => {
				log::debug!("Identify request pushed to {:?}", peer_id);
			},
			IdentifyEvent::Error { peer_id, error } => {
				log::error!("Identify error {:?} from {:?}", error, peer_id);
			},
		}
	}

	/// A method for handling the swarm events.
	pub fn handle_swarm_events(
		&mut self,
		event: SwarmEvent<
			EigenEvent,
			EitherError<ConnectionHandlerUpgrErr<IoError>, std::io::Error>,
		>,
	) {
		match event {
			SwarmEvent::Behaviour(EigenEvent::RequestResponse(event)) => {
				self.handle_req_res_events(event);
			},
			SwarmEvent::Behaviour(EigenEvent::Identify(event)) => {
				self.handle_identify_events(event);
			},
			SwarmEvent::NewListenAddr { address, .. } => {
				log::info!("Listening on {:?}", address);
			},
			// When we connect to a peer, we automatically add him as a neighbor.
			SwarmEvent::ConnectionEstablished { peer_id, .. } => {
				let res = self.peer.add_neighbor(peer_id);
				if let Err(e) = res {
					log::error!("Failed to add neighbor {:?}", e);
				}
				log::info!("Connection established with {:?}", peer_id);
				// Send identify request
				let request = Request::Identify(self.peer.pubkey.clone());
				self.swarm.behaviour_mut().send_request(&peer_id, request);
			},
			// When we disconnect from a peer, we automatically remove him from the neighbors list.
			SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
				self.peer.remove_neighbor(peer_id);
				log::info!("Connection closed with {:?} ({:?})", peer_id, cause);
			},
			SwarmEvent::Dialing(peer_id) => {
				log::info!("Dialing {:?}", peer_id);
			},
			e => {
				log::debug!("{:?}", e);
			},
		}
	}

	/// Dial the neighbor directly.
	pub fn dial_neighbor(&mut self, addr: Multiaddr) {
		let res = self.swarm.dial(addr).map_err(|_| EigenError::DialError);
		log::debug!("swarm.dial {:?}", res);
	}

	/// Send the request for an Ivp to all neighbors, in the passed epoch and
	/// iteration.
	pub fn send_epoch_requests(&mut self, epoch: Epoch, k: u32) {
		for peer_id in self.peer.neighbors() {
			let ivp = self.peer.calculate_local_ivp(peer_id, epoch, k).unwrap();
			assert_eq!(ivp.iter, k + 1);
			let request = Request::Ivp(ivp);
			self.swarm.behaviour_mut().send_request(&peer_id, request);
		}
	}

	/// Send the request for an Ivp to all neighbors, in the passed epoch and
	/// iteration.
	pub fn send_initial_epoch_requests(&mut self, epoch: Epoch) {
		for peer_id in self.peer.neighbors() {
			let ivp = self.peer.calculate_initial_ivp(peer_id, epoch).unwrap();
			assert_eq!(ivp.iter, 0);
			let request = Request::Ivp(ivp);
			self.swarm.behaviour_mut().send_request(&peer_id, request);
		}
	}

	/// Start the main loop of the program. This function has two main tasks:
	/// - To start an interval timer for sending the request for Ivps.
	/// - To handle the swarm + request/response events.
	/// The amount of intervals/epochs is determined by the `interval_limit`
	/// parameter.
	pub async fn main_loop(mut self, interval_limit: usize) {
		let now = Instant::now();
		// Set up epoch interval
		let epoch_interval = Duration::from_secs(EPOCH_INTERVAL);
		let iter_interval = Duration::from_secs(ITER_INTERVAL);
		let secs_until_next_epoch = Epoch::secs_until_next_epoch(epoch_interval.as_secs());
		log::info!("Epoch starts in: {} seconds", secs_until_next_epoch);
		// Figure out when the next epoch will start.
		let start = now + Duration::from_secs(secs_until_next_epoch);
		// Setup the epoch interval timer.
		let mut outer_interval = create_iter(start, epoch_interval, interval_limit);
		let mut inner_interval = create_iter(Instant::now(), iter_interval, usize::MAX);

		loop {
			select_biased! {
				// The interval timer tick. This is where we create new iteration interval
				epoch = outer_interval.select_next_some() => {
					log::info!("Epoch({}) has started", epoch);
					self.send_initial_epoch_requests(Epoch(epoch));
				},
				tick = inner_interval.select_next_some() => {
					let epoch = Epoch::current_epoch(EPOCH_INTERVAL);
					// If we collected the Ivps from all the neighbours in one iteration
					// We create the Ivp for the next iteration and distribute it

					for iter in 0..NUM_ITERATIONS {
						if !self.peer.has_all_neighbour_proofs_at(epoch, iter) {
							continue;
						}

						for peer_id in self.peer.neighbors() {
							let ivp = self.peer.calculate_local_ivp(peer_id, epoch, iter).unwrap();
							assert_eq!(ivp.iter, iter + 1);
							let request = Request::Ivp(ivp);
							// self.swarm.behaviour_mut().send_request(&peer_id, request);
						}
					}
				}
				// The swarm event.
				event = self.swarm.select_next_some() => {
					self.handle_swarm_events(event);
				},
				complete => break,
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		constants::{MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS},
		peer::{ivp::Ivp, pubkey::Pubkey},
		utils::keypair_from_sk_bytes,
	};
	use eigen_trust_circuit::{
		halo2wrong::{
			curves::bn256::Bn256,
			halo2::poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
		},
		params::poseidon_bn254_5x5::Params,
		utils::{keygen, random_circuit},
	};
	use futures::{channel::oneshot, select};
	use libp2p::{
		core::{connection::ConnectionId, ConnectedPoint, Endpoint},
		identify::{IdentifyEvent, IdentifyInfo},
		request_response::{
			handler::RequestResponseHandlerEvent, RequestResponseEvent, RequestResponseMessage,
		},
	};
	use rand::thread_rng;
	use std::{num::NonZeroU32, str::FromStr};
	use tokio::time::sleep;

	const ADDR_1: &str = "/ip4/127.0.0.1/tcp/56706";
	const ADDR_2: &str = "/ip4/127.0.0.1/tcp/58601";
	const SK_1: &str = "AF4yAqwCPzpBcit4FtTrHso4BBR9onk7qS9Q1SWSLSaV";
	const SK_2: &str = "7VoQFngkSo36s5yzZtnjtZ5SLe1VGukCZdb5Uc9tSDNC";

	async fn await_swarm_events(node1: &mut Node, node2: &mut Node, i: usize) {
		for _ in 0..i {
			select_biased! {
				ev1 = node1.swarm.select_next_some() => {
					println!("{:?}", ev1);
					node1.handle_swarm_events(ev1);
				},
				ev2 = node2.swarm.select_next_some() => {
					println!("{:?}", ev2);
					node2.handle_swarm_events(ev2);
				},
				complete => break,
			}
		}
	}

	#[test]
	fn should_add_neighbour_on_connection() {
		let sk_bytes1 = bs58::decode(SK_1).into_vec().unwrap();
		let sk_bytes2 = bs58::decode(SK_2).into_vec().unwrap();

		let local_key1 = keypair_from_sk_bytes(sk_bytes1).unwrap();
		let peer_id1 = local_key1.public().to_peer_id();

		let local_key2 = keypair_from_sk_bytes(sk_bytes2).unwrap();
		let peer_id2 = local_key2.public().to_peer_id();

		let local_address1 = Multiaddr::from_str(ADDR_1).unwrap();
		let local_address2 = Multiaddr::from_str(ADDR_2).unwrap();

		let params = ParamsKZG::new(9);

		let rng = &mut thread_rng();
		let random_circuit =
			random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params>(rng);
		let pk = keygen(&params, &random_circuit).unwrap();

		let peer1 = Peer::new(local_key1.clone(), params.clone(), pk.clone()).unwrap();
		let peer2 = Peer::new(local_key2.clone(), params, pk).unwrap();

		let mut node1 = Node::new(local_key1, local_address1.clone(), peer1).unwrap();
		let mut node2 = Node::new(local_key2, local_address2.clone(), peer2).unwrap();

		let conn_event1 = SwarmEvent::ConnectionEstablished {
			peer_id: peer_id1,
			endpoint: ConnectedPoint::Dialer {
				address: local_address1,
				role_override: Endpoint::Dialer,
			},
			num_established: NonZeroU32::new(1u32).unwrap(),
			concurrent_dial_errors: None,
		};
		let conn_event2 = SwarmEvent::ConnectionEstablished {
			peer_id: peer_id2,
			endpoint: ConnectedPoint::Dialer {
				address: local_address2,
				role_override: Endpoint::Dialer,
			},
			num_established: NonZeroU32::new(1u32).unwrap(),
			concurrent_dial_errors: None,
		};
		node2.handle_swarm_events(conn_event1);
		node1.handle_swarm_events(conn_event2);

		assert_eq!(node2.peer.neighbors(), vec![peer_id1]);
		assert_eq!(node1.peer.neighbors(), vec![peer_id2]);
	}

	#[test]
	fn should_identify_neighbors() {
		let sk_bytes1 = bs58::decode(SK_1).into_vec().unwrap();
		let sk_bytes2 = bs58::decode(SK_2).into_vec().unwrap();

		let local_key1 = keypair_from_sk_bytes(sk_bytes1).unwrap();
		let pub_key1 = local_key1.public();
		let peer_id1 = pub_key1.to_peer_id();

		let local_key2 = keypair_from_sk_bytes(sk_bytes2).unwrap();
		let pub_key2 = local_key2.public();
		let peer_id2 = pub_key2.to_peer_id();

		let local_address1 = Multiaddr::from_str(ADDR_1).unwrap();
		let local_address2 = Multiaddr::from_str(ADDR_2).unwrap();

		let params = ParamsKZG::new(9);

		let rng = &mut thread_rng();
		let random_circuit =
			random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params>(rng);
		let pk = keygen(&params, &random_circuit).unwrap();

		let peer1 = Peer::new(local_key1.clone(), params.clone(), pk.clone()).unwrap();
		let peer2 = Peer::new(local_key2.clone(), params, pk).unwrap();

		let mut node1 = Node::new(local_key1.clone(), local_address1.clone(), peer1).unwrap();
		let mut node2 = Node::new(local_key2.clone(), local_address2.clone(), peer2).unwrap();

		let identify_event1 = IdentifyEvent::Received {
			peer_id: peer_id1,
			info: IdentifyInfo {
				public_key: pub_key1.clone(),
				protocol_version: String::from("eigen_trust/1.0.0"),
				agent_version: String::from("foo"),
				listen_addrs: vec![local_address1.clone()],
				protocols: vec![String::from("eigen_trust")],
				observed_addr: local_address1,
			},
		};
		let identify_event2 = IdentifyEvent::Received {
			peer_id: peer_id2,
			info: IdentifyInfo {
				public_key: pub_key2.clone(),
				protocol_version: String::from("eigen_trust/1.0.0"),
				agent_version: String::from("foo"),
				listen_addrs: vec![local_address2.clone()],
				protocols: vec![String::from("eigen_trust")],
				observed_addr: local_address2,
			},
		};
		node2.handle_identify_events(identify_event1);
		node1.handle_identify_events(identify_event2);

		let pubkey1 = node2.peer.get_pub_key_native(peer_id1).unwrap();
		let pubkey2 = node1.peer.get_pub_key_native(peer_id2).unwrap();
		assert_eq!(pubkey1, pub_key1);
		assert_eq!(pubkey2, pubkey2);
	}

	#[tokio::test]
	async fn should_handle_request_for_ivp() {
		let sk_bytes1 = bs58::decode(SK_1).into_vec().unwrap();
		let sk_bytes2 = bs58::decode(SK_2).into_vec().unwrap();

		let local_key1 = keypair_from_sk_bytes(sk_bytes1).unwrap();
		let peer_id1 = local_key1.public().to_peer_id();
		let pubkey1 = Pubkey::from_keypair(&local_key1).unwrap();

		let local_key2 = keypair_from_sk_bytes(sk_bytes2).unwrap();
		let peer_id2 = local_key2.public().to_peer_id();
		let pubkey2 = Pubkey::from_keypair(&local_key2).unwrap();

		let local_address1 = Multiaddr::from_str(ADDR_1).unwrap();
		let local_address2 = Multiaddr::from_str(ADDR_2).unwrap();

		let params = ParamsKZG::new(9);

		let rng = &mut thread_rng();
		let random_circuit =
			random_circuit::<Bn256, _, MAX_NEIGHBORS, NUM_BOOTSTRAP_PEERS, Params>(rng);
		let pk = keygen(&params, &random_circuit).unwrap();

		let peer1 = Peer::new(local_key1.clone(), params.clone(), pk.clone()).unwrap();
		let peer2 = Peer::new(local_key2.clone(), params, pk).unwrap();

		let mut node1 = Node::new(local_key1, local_address1.clone(), peer1).unwrap();
		let mut node2 = Node::new(local_key2, local_address2.clone(), peer2).unwrap();

		node1.peer.set_score(peer_id2, 5);
		node2.peer.set_score(peer_id1, 5);

		let epoch = Epoch(3);
		let iter = 0;

		node1.dial_neighbor(local_address2);

		await_swarm_events(&mut node1, &mut node2, 9).await;

		node1.send_initial_epoch_requests(epoch);
		node2.send_initial_epoch_requests(epoch);

		sleep(Duration::from_secs(2)).await;
		await_swarm_events(&mut node1, &mut node2, 12).await;

		let peer1_neighbor_ivp =
			node1.peer.cached_neighbor_ivp.get(&(peer_id2, epoch, iter)).unwrap();
		let peer2_neighbor_ivp =
			node2.peer.cached_neighbor_ivp.get(&(peer_id1, epoch, iter)).unwrap();

		assert_eq!(peer1_neighbor_ivp.epoch, Epoch(3));
		assert_eq!(peer1_neighbor_ivp.op, 0.5);

		assert_eq!(peer2_neighbor_ivp.epoch, Epoch(3));
		assert_eq!(peer2_neighbor_ivp.op, 0.5);
	}
}
