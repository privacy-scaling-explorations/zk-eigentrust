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
use std::{io::Error as IoError, iter::once};
use tokio::{
	select,
	time::{self, Duration, Instant},
};

pub struct Node {
	swarm: Swarm<RequestResponse<EigenTrustCodec>>,
	peer: Peer,
	local_key: Keypair,
	bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
	interval: u64,
}

impl Node {
	pub fn new(
		local_key: Keypair,
		local_address: Multiaddr,
		bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
		num_neighbours: usize,
		interval: u64,
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
		let req_proto = RequestResponse::new(EigenTrustCodec, protocols, cfg);

		// Setting up the transport and swarm.
		let local_peer_id = PeerId::from(local_key.public());
		let num_connections =
			u32::try_from(num_neighbours).map_err(|_| EigenError::InvalidNumNeighbours)?;
		let connection_limits =
			ConnectionLimits::default().with_max_established_per_peer(Some(num_connections));

		let mut swarm = SwarmBuilder::new(transport, req_proto, local_peer_id)
			.connection_limits(connection_limits)
			.build();

		swarm.listen_on(local_address).map_err(|e| {
			log::debug!("swarm.listen_on {:?}", e);
			EigenError::ListenFailed
		})?;

		let peer = Peer::new(num_neighbours);

		Ok(Self {
			swarm,
			peer,
			local_key,
			bootstrap_nodes,
			interval,
		})
	}

	pub fn handle_req_res_events(
		&mut self,
		event: RequestResponseEvent<Request, Response>,
	) -> Result<(), EigenError> {
		log::debug!("ReqRes event {:?}", event);
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
				self.peer.calculate_local_opinions(request.get_epoch())?;
				let opinion = self.peer.get_local_opinion(&(peer, request.get_epoch()));
				let response = Response::Success(opinion);
				beh.send_response(channel, response)
					.map_err(|_| EigenError::ResponseError)?;
			},
			Message {
				peer,
				message: Res { response, .. },
			} => {
				if let Response::Success(opinion) = response {
					self.peer
						.cache_neighbour_opinion((peer, opinion.get_epoch()), opinion);
				} else {
					log::debug!("Received error response {:?}", response);
				}
			},
			OutboundFailure {
				peer, request_id, ..
			} => {
				log::debug!("Outbound failure {:?} from {:?}", request_id, peer);
			},
			InboundFailure {
				peer, request_id, ..
			} => {
				log::debug!("Inbound failure {:?} from {:?}", request_id, peer);
			},
			ResponseSent { peer, request_id } => {
				log::debug!("Response sent {:?} to {:?}", request_id, peer);
			},
		};
		Ok(())
	}

	pub fn handle_swarm_events(
		&mut self,
		event: SwarmEvent<
			RequestResponseEvent<Request, Response>,
			ConnectionHandlerUpgrErr<IoError>,
		>,
	) -> Result<(), EigenError> {
		match event {
			SwarmEvent::NewListenAddr { address, .. } => log::info!("Listening on {:?}", address),
			SwarmEvent::Behaviour(req_res_event) => self.handle_req_res_events(req_res_event)?,
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

		Ok(())
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

	pub fn send_epoch_requests(&mut self) -> Result<(), EigenError> {
		let current_epoch = Epoch::current_epoch(self.interval)?;
		let timestamp = Epoch::current_timestamp()?;
		let score = self.peer.get_global_score(current_epoch.previous());
		log::info!(
			"{}, Timestamp {}, Previous Epoch Score: {}",
			current_epoch,
			timestamp,
			score
		);

		self.peer.iter_neighbours(|peer_id| {
			let beh = self.swarm.behaviour_mut();

			let request = Request::new(current_epoch);
			beh.send_request(&peer_id, request);
			Ok(())
		})?;
		Ok(())
	}

	pub async fn main_loop(mut self) -> Result<(), EigenError> {
		println!();

		self.dial_bootstrap_nodes();

		let now = Instant::now();
		let secs_until_next_epoch = Epoch::secs_until_next_epoch(self.interval)?;
		let start = now + Duration::from_secs(secs_until_next_epoch);
		let period = Duration::from_secs(self.interval);

		let mut interval = time::interval_at(start, period);

		loop {
			select! {
				biased;
				_ = interval.tick() => self.send_epoch_requests()?,
				event = self.swarm.select_next_some() => self.handle_swarm_events(event)?,
			}
		}
	}
}
