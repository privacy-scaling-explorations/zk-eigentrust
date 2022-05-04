use libp2p::{
	core::upgrade::Version,
	identity::Keypair,
	noise::{Keypair as NoiseKeypair, NoiseConfig, X25519Spec},
	request_response::{
		ProtocolSupport, RequestResponse, RequestResponseConfig, RequestResponseEvent, RequestResponseMessage, RequestId
	},
	swarm::{ConnectionHandlerUpgrErr, ConnectionLimits, Swarm, SwarmBuilder, SwarmEvent},
	tcp::TcpConfig,
	yamux::YamuxConfig,
	Multiaddr, PeerId, Transport,
};

use std::{io::Error as IoError, iter::once, time::Duration, collections::HashMap};

use futures::prelude::*;

use crate::{
	protocol::{EigenTrustCodec, EigenTrustProtocol, Request, Response},
	EigenError, Peer,
};

pub struct Node<const N: usize> {
	swarm: Swarm<RequestResponse<EigenTrustCodec>>,
	peer: Peer<N>,
	local_key: Keypair,
	bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
	cached_outgoing_responses: HashMap<(PeerId, u32), Response>,
	cached_local_responses: HashMap<(PeerId, u32), Response>,
	active_requests: HashMap<RequestId, Request>,
}

impl<const N: usize> Node<N> {
	pub fn new(
		peer: Peer<N>,
		local_key: Keypair,
		local_address: Multiaddr,
		bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
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
			.timeout(Duration::from_secs(20))
			.boxed();

		// Setting up the request/response protocol.
		let protocols = once((EigenTrustProtocol::new(), ProtocolSupport::Full));
		let cfg = RequestResponseConfig::default();
		let req_proto = RequestResponse::new(EigenTrustCodec, protocols.clone(), cfg.clone());

		// Setting up the transport and swarm.
		let local_peer_id = PeerId::from(local_key.public());
		let num_connections = u32::try_from(N).map_err(|_| EigenError::InvalidNeighbourCount)?;
		let connection_limits =
			ConnectionLimits::default().with_max_established_per_peer(Some(num_connections));

		let mut swarm = SwarmBuilder::new(transport, req_proto, local_peer_id)
			.connection_limits(connection_limits)
			.build();

		swarm.listen_on(local_address.clone()).map_err(|e| {
			log::debug!("swarm.listen_on {:?}", e);
			EigenError::ListenFailed
		})?;

		Ok(Self {
			swarm,
			peer,
			local_key,
			bootstrap_nodes,
			cached_local_responses: HashMap::new(),
			cached_outgoing_responses: HashMap::new(),
			active_requests: HashMap::new(),
		})
	}

	pub fn handle_req_res_events(&mut self, event: RequestResponseEvent<Request, Response>) {
		log::debug!("ReqRes event {:?}", event);
		use RequestResponseEvent::*;
		use RequestResponseMessage::{Request as Req, Response as Res};
		match event {
			Message { peer, message: Req { request, .. } } => {
				log::debug!("Request from {:?}: {:?}", peer, request);
			}
			Message { peer, message: Res { response, .. } } => {
				log::debug!("Response from {:?}: {:?}", peer, response);
			}
			OutboundFailure { peer, request_id, .. } => {
				log::debug!("Outbound failure {:?} from {:?}", request_id, peer);
			}
			InboundFailure { peer, request_id, .. } => {
				log::debug!("Inbound failure {:?} from {:?}", request_id, peer);
			}
			ResponseSent { peer, request_id } => {
				log::debug!("Response sent {:?} to {:?}", request_id, peer);
			}
		}
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
				let res = self.peer.remove_neighbour(peer_id);
				if let Err(e) = res {
					log::error!("Failed to remove neighbour {:?}", e);
				}
				log::info!("Connection closed with {:?} ({:?})", peer_id, cause);
			},
			SwarmEvent::Dialing(peer_id) => log::info!("Dialing {:?}", peer_id),
			e => log::debug!("{:?}", e),
		}
	}

	pub fn dial_bootstrap_nodes(&mut self) {
		// We want to connect to all bootstrap nodes.
		let local_peer_id = self.local_key.public().to_peer_id();
		for (peer_id, peer_addr) in &self.bootstrap_nodes {
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

	pub async fn main_loop(&mut self) {
		println!();

		self.dial_bootstrap_nodes();

		loop {
			let event = self.swarm.select_next_some().await;
			self.handle_swarm_events(event);
		}
	}
}
