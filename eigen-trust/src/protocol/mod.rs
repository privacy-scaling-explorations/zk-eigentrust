pub mod req_res;

use std::{iter::once, time::Duration};
use req_res::{EigenTrustCodec, Request, Response, EigenTrustProtocol};
use crate::{peer::Peer, Epoch, EigenError};
use libp2p::{
	PeerId,
	identify::{Identify, IdentifyConfig, IdentifyEvent},
	swarm::NetworkBehaviourEventProcess,
	request_response::{
		RequestResponse,
		RequestResponseEvent,
		RequestResponseMessage,
		RequestResponseConfig,
		ProtocolSupport,
		ResponseChannel, RequestId,
	},
	NetworkBehaviour, core::PublicKey,
};

#[derive(NetworkBehaviour)]
#[behaviour(event_process = true)]
pub struct EigenTrustBehaviour {
	req_res: RequestResponse<EigenTrustCodec>,
	identify: Identify,
	#[behaviour(ignore)]
	peer: Peer,
}

impl EigenTrustBehaviour {
	pub fn new(
		connection_duration: Duration,
		interval_duration: Duration,
		local_public_key: PublicKey,
		peer: Peer,
	) -> Self {
		// Setting up the request/response protocol.
		let protocols = once((EigenTrustProtocol::new(), ProtocolSupport::Full));
		let mut cfg = RequestResponseConfig::default();
		// Keep the connection alive in request/response protocol
		cfg.set_connection_keep_alive(connection_duration);
		// If we failed to get response during the interval duration, cancel it.
		cfg.set_request_timeout(interval_duration);
		let req_proto = RequestResponse::new(EigenTrustCodec, protocols, cfg);

		// Setting up the identify protocol
		let config = IdentifyConfig::new("eigen_trust/1.0.0".to_string(), local_public_key);
		let identify = Identify::new(config);
		Self { req_res: req_proto, identify, peer }
	}

	pub fn send_response(&mut self, channel: ResponseChannel<Response>, response: Response) -> Result<(), Response> {
		self.req_res.send_response(channel, response)
	}

	pub fn send_request(&mut self, peer_id: &PeerId, request: Request) -> RequestId {
		self.req_res.send_request(peer_id, request)
	}

	/// Get the peer struct.
	pub fn get_peer(&self) -> &Peer {
		&self.peer
	}

	/// Get the mutable peer struct.
	pub fn get_peer_mut(&mut self) -> &mut Peer {
		&mut self.peer
	}

	/// Send the request for an opinion to all neighbors, in the passed epoch.
	pub fn send_epoch_requests(&mut self, epoch: Epoch) {
		for peer_id in self.peer.neighbors() {
			let request = Request::new(epoch);
			self.req_res.send_request(&peer_id, request);
		}
	}

	pub fn global_trust_score_at(&self, at: Epoch) -> f64 {
		self.peer.calculate_global_trust_score(at)
	}
}

impl NetworkBehaviourEventProcess<RequestResponseEvent<Request, Response>> for EigenTrustBehaviour {
	fn inject_event(&mut self, event: RequestResponseEvent<Request, Response>) {
		use RequestResponseEvent::*;
		use RequestResponseMessage::{Request as Req, Response as Res};
		match event {
			Message {
				peer,
				message: Req {
					request, channel, ..
				},
			} => {
				// First we calculate the local opinions for the requested epoch.
				self.peer.calculate_local_opinions(request.get_epoch());
				// Then we send the local opinion to the peer.
				let opinion = self.peer.get_local_opinion(&(peer, request.get_epoch()));
				let response = Response::Success(opinion);
				let res = self.req_res.send_response(channel, response);
				if let Err(e) = res {
					log::error!("Failed to send the response {:?}", e);
				}
			},
			Message {
				peer,
				message: Res { response, .. },
			} => {
				// If we receive a response, we update the neighbors's opinion about us.
				// TODO: Check the validity of the opinion, by verifying a zero-knowledge proof.
				if let Response::Success(opinion) = response {
					self.peer
						.cache_neighbor_opinion((peer, opinion.get_epoch()), opinion);
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
}

impl NetworkBehaviourEventProcess<IdentifyEvent> for EigenTrustBehaviour {
	fn inject_event(&mut self, event: IdentifyEvent) {
		match event {
			IdentifyEvent::Received { peer_id, info } => {
				let res = self.peer.identify_neighbor(peer_id, info.public_key);
				if let Err(EigenError::InvalidPeerId) = res {
					log::error!("Received invalid peer id {:?}", peer_id);
				}
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
}