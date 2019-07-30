// Copyright 2019 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

//! Substrate network entry point.

use crate::NetworkStatus;
use client::BlockchainEvents;
use consensus_common_primitives::ConsensusApi;
use futures::{prelude::*, sync::mpsc};
use futures03::stream::{StreamExt, TryStreamExt};
use libp2p::Multiaddr;
use log::{log, warn, Level};
use network::{DhtEvent, Event};
use offchain::AuthorityKeyProvider as _;
use parking_lot::Mutex;
use sr_primitives::{generic::BlockId, traits::ProvideRuntimeApi};
use std::time::{Duration, Instant};

use crate::components::{
    ComponentAuthorityKeyProvider, ComponentBlock, ComponentClient, Components, ServiceFactory,
};
use network::NetworkState;
use network::{self, NetworkStateInfo};
use primitives::Pair;
use std::sync::Arc;

// TODO %s/Builder//
pub trait NetworkFutureBuilder<C: Components> {
    fn build_network_future<H, S>(
        network: network::NetworkWorker<ComponentBlock<C>, S, H>,
        client: Arc<ComponentClient<C>>,
        status_sinks: Arc<
            Mutex<Vec<mpsc::UnboundedSender<(NetworkStatus<ComponentBlock<C>>, NetworkState)>>>,
        >,
        rpc_rx: mpsc::UnboundedReceiver<rpc::apis::system::Request<ComponentBlock<C>>>,
        should_have_peers: bool,
        authority_key_provider: ComponentAuthorityKeyProvider<C>,
    ) -> Box<dyn Future<Item = (), Error = ()> + Send>
    where
        H: network::ExHashT,
        S: network::specialization::NetworkSpecialization<ComponentBlock<C>>;
}

impl<C: Components> NetworkFutureBuilder<Self> for C
where
	ComponentClient<C>: ProvideRuntimeApi,
<ComponentClient<C> as ProvideRuntimeApi>::Api: ConsensusApi<ComponentBlock<C>, <C::Factory as ServiceFactory>::AuthorityId>,
<<<C as Components>::Factory as ServiceFactory>::ConsensusPair as primitives::crypto::Pair>::Public : std::string::ToString,
{
	fn build_network_future<H, S>(
		network: network::NetworkWorker<ComponentBlock<C>,  S, H>,
		client: Arc<ComponentClient<C>>,
		status_sinks: Arc<Mutex<Vec<mpsc::UnboundedSender<(NetworkStatus<ComponentBlock<C>>, NetworkState)>>>>,
		rpc_rx: mpsc::UnboundedReceiver<rpc::apis::system::Request<ComponentBlock<C>>>,
		should_have_peers: bool,
		authority_key_provider: ComponentAuthorityKeyProvider<C>,
	)-> Box<dyn Future<Item = (), Error = ()> + Send>
	where
		H: network::ExHashT,
		S:network::specialization::NetworkSpecialization<ComponentBlock<C>>,
	{
		// Interval at which we send status updates on the status stream.
		const STATUS_INTERVAL: Duration = Duration::from_millis(5000);
		let status_interval = tokio_timer::Interval::new_interval(STATUS_INTERVAL);

		let report_ext_addresses_interval = tokio_timer::Interval::new_interval(Duration::from_secs(5));


		let imported_blocks_stream = Box::new(client.import_notification_stream().fuse()
											  .map(|v| Ok::<_, ()>(v)).compat());
		let finality_notification_stream = Box::new(client.finality_notification_stream().fuse()
													.map(|v| Ok::<_, ()>(v)).compat());

		Box::new(NetworkFuture::<C, H, S>{
			authority_key_provider,
			client,
			ext_addr_interval: report_ext_addresses_interval,
			finality_notification_stream,
			imported_blocks_stream,
			network,
			rpc_rx,
			should_have_peers,
			status_interval,
			status_sinks
		})
	}
}

struct NetworkFuture<C, H, S>
where
    C: Components,
    H: network::ExHashT,
    S: network::specialization::NetworkSpecialization<ComponentBlock<C>>,
{
    authority_key_provider: ComponentAuthorityKeyProvider<C>,
    client: Arc<ComponentClient<C>>,
    ext_addr_interval: tokio_timer::Interval,
    finality_notification_stream:
        Box<dyn Stream<Item = client::FinalityNotification<ComponentBlock<C>>, Error = ()> + Send>,
    imported_blocks_stream: Box<
        dyn Stream<Item = client::BlockImportNotification<ComponentBlock<C>>, Error = ()> + Send,
    >,
    network: network::NetworkWorker<ComponentBlock<C>, S, H>,
    rpc_rx: mpsc::UnboundedReceiver<rpc::apis::system::Request<ComponentBlock<C>>>,
    should_have_peers: bool,
    status_interval: tokio_timer::Interval,
    status_sinks:
        Arc<Mutex<Vec<mpsc::UnboundedSender<(NetworkStatus<ComponentBlock<C>>, NetworkState)>>>>,
}

impl<C, H, S> futures::future::Future for NetworkFuture<C, H, S>
where
	C: Components,
ComponentClient<C>: ProvideRuntimeApi,
<ComponentClient<C> as ProvideRuntimeApi>::Api: ConsensusApi<ComponentBlock<C>, <C::Factory as ServiceFactory>::AuthorityId>,
<<<C as Components>::Factory as ServiceFactory>::ConsensusPair as primitives::crypto::Pair>::Public : std::string::ToString,
	H: network::ExHashT,
	S:network::specialization::NetworkSpecialization<ComponentBlock<C>>,
{
	type Item = ();
	type Error = ();

	fn poll(&mut self) -> Result<Async<()>, ()> {
		let before_polling = Instant::now();

		self.poll_imported_blocks_stream();

		while let Ok(Async::Ready(_)) = self.ext_addr_interval.poll() {
			println!("==== We are connected to {} nodes", self.network.service().num_connected());

			self.put_external_addresses_on_dht();
			self.query_addresses_of_other_validators();
		}

		self.poll_finality_notification_stream();

		self.poll_rpc_requests();

		self.report_network_status();


		// Main network polling.
		while let Ok(Async::Ready(Some(Event::Dht(event)))) = self.network.poll().map_err(|err| {
			warn!(target: "service", "Error in network: {:?}", err);
		}) {
			match event {
				DhtEvent::ValueFound(values) => self.connect_to_validator(values),
				DhtEvent::ValueNotFound(_h) => println!("==== Didn't find hash"),
				DhtEvent::ValuePut(_h) => {},
				DhtEvent::ValuePutFailed(_h) => println!("==== failed to put value on DHT"),
			}
		};

		// Now some diagnostic for performances.
		let polling_dur = before_polling.elapsed();
		log!(
			target: "service",
			if polling_dur >= Duration::from_millis(50) { Level::Warn } else { Level::Trace },
			"Polling the network future took {:?}",
			polling_dur
		);

		Ok(Async::NotReady)
	}
}

impl<C, H, S> NetworkFuture<C, H, S>
where
	C: Components,
ComponentClient<C>: ProvideRuntimeApi,
<ComponentClient<C> as ProvideRuntimeApi>::Api: ConsensusApi<ComponentBlock<C>, <C::Factory as ServiceFactory>::AuthorityId>,
<<<C as Components>::Factory as ServiceFactory>::ConsensusPair as primitives::crypto::Pair>::Public : std::string::ToString,
	H: network::ExHashT,
	S:network::specialization::NetworkSpecialization<ComponentBlock<C>>,
{

	fn poll_imported_blocks_stream(&mut self) {
		// We poll `imported_blocks_stream`.
		while let Ok(Async::Ready(Some(notification))) = self.imported_blocks_stream.poll() {
			self.network.on_block_imported(notification.hash, notification.header);
		}
	}

	fn put_external_addresses_on_dht(&mut self) {
		let id = BlockId::hash( self.client.info().chain.best_hash);
		// Put our addresses on the DHT if we are a validator.
		if let Some(authority_key) = self.authority_key_provider.authority_key( &id) {
			let public_key = authority_key.public().to_string();

			let hashed_public_key = libp2p::multihash::encode(
				libp2p::multihash::Hash::SHA2256,
				&public_key.as_bytes(),
			).expect("public key hashing not to fail");

			let addresses: Vec<Multiaddr> = self.network.service().external_addresses()
				.iter()
				.map(|a| {
					let mut a = a.clone();
					a.push(libp2p::core::multiaddr::Protocol::P2p(self.network.service().peer_id().into()));
					a
				})
				.collect();
			println!("==== external addresses: {:?}", addresses);

			// TODO: Remove unwrap.
			let signature = authority_key.sign(
				&serde_json::to_string(&addresses)
					.map(|s| s.into_bytes())
					.expect("enriched_address marshaling not to fail")
			).as_ref().to_vec();

			// TODO: Remove unwrap.
			let payload = serde_json::to_string(&(addresses, signature)).expect("payload marshaling not to fail");

			self.network.service().put_value(hashed_public_key, payload.into_bytes());
		}
	}

	fn query_addresses_of_other_validators(&mut self) {
		let id = BlockId::hash( self.client.info().chain.best_hash);
		// Query addresses of other validators.
		// TODO: Should non-validators also do this? Probably not a good default.
		match self.client.runtime_api().authorities(&id) {
			Ok(authorities) => {
				for authority in authorities.iter() {
					println!("==== querying dht for authority: {}", authority.to_string());
					// TODO: Remove unwrap.
					let hashed_public_key = libp2p::multihash::encode(
						libp2p::multihash::Hash::SHA2256,
						authority.to_string().as_bytes(),
					).expect("public key hashing not to fail");

					self.network.service().get_value(&hashed_public_key.clone());
				}
			},
			Err(e) => {
				println!("==== Got no authorities, but an error: {:?}", e);
			}
		}
	}

	fn poll_finality_notification_stream(&mut self) {
		// We poll `finality_notification_stream`, but we only take the last event.
		let mut last = None;
		while let Ok(Async::Ready(Some(item))) = self.finality_notification_stream.poll() {
			last = Some(item);
		}
		if let Some(notification) = last {
			self.network.on_block_finalized(notification.hash, notification.header);
		}
	}

	fn poll_rpc_requests(&mut self) {
		// Poll the RPC requests and answer them.
		while let Ok(Async::Ready(Some(request))) = self.rpc_rx.poll() {
			match request {
				rpc::apis::system::Request::Health(sender) => {
					let _ = sender.send(rpc::apis::system::Health {
						peers: self.network.peers_debug_info().len(),
						is_syncing: self.network.service().is_major_syncing(),
						should_have_peers: self.should_have_peers,
					});
				},
				rpc::apis::system::Request::Peers(sender) => {
					let _ = sender.send(self.network.peers_debug_info().into_iter().map(|(peer_id, p)|
																						rpc::apis::system::PeerInfo {
																							peer_id: peer_id.to_base58(),
																							roles: format!("{:?}", p.roles),
																							protocol_version: p.protocol_version,
																							best_hash: p.best_hash,
																							best_number: p.best_number,
																						}
					).collect());
				}
				rpc::apis::system::Request::NetworkState(sender) => {
					let _ = sender.send(self.network.network_state());
				}
			};
		}
	}

	fn report_network_status(&mut self) {
		// Interval report for the external API.
		while let Ok(Async::Ready(_)) = self.status_interval.poll() {
			let status = NetworkStatus {
				sync_state: self.network.sync_state(),
				best_seen_block: self.network.best_seen_block(),
				num_sync_peers: self.network.num_sync_peers(),
				num_connected_peers: self.network.num_connected_peers(),
				num_active_peers: self.network.num_active_peers(),
				average_download_per_sec: self.network.average_download_per_sec(),
				average_upload_per_sec: self.network.average_upload_per_sec(),
			};
			let state = self.network.network_state();

			self.status_sinks.lock().retain(|sink| sink.unbounded_send((status.clone(), state.clone())).is_ok());
		}
	}

	fn connect_to_validator(&mut self, values: Vec<(libp2p::multihash::Multihash, Vec<u8>)>) {
		let authorities = self.client.runtime_api().authorities(&BlockId::hash(self.client.info().chain.best_hash));
		let valid_authority = |a: &libp2p::multihash::Multihash| {
			match &authorities {
				Ok(authorities) => {
					for authority in authorities.iter() {
						let hashed_public_key = libp2p::multihash::encode(
							libp2p::multihash::Hash::SHA2256,
							authority.to_string().as_bytes(),
						).expect("public key hashing not to fail");

						// TODO: Comparing two pointers is safe, right? Given they are not fat-pointers.
						if a == &hashed_public_key {
							return Some(authority.clone());
						}
					}
				},
				// TODO: Should we handle the error here?
				Err(_e) => {},
			}

			return None;
		};

		// TODO: Can we do this nicer?
		let network_service = self.network.service().clone();
		for (key, value) in values.iter() {
			// TODO: Should we log if it is not a valid one?
			if let Some(authority_pub_key) = valid_authority(key) {
				println!("===== adding other node");
				let value = std::str::from_utf8(value).expect("value to string not to fail");

				let (addresses, signature): (Vec<Multiaddr>, Vec<u8>) = serde_json::from_str(value).expect("payload unmarshaling not to fail");

				// TODO: is using verify-weak a problem here?
				if <<C as Components>::Factory as ServiceFactory>::ConsensusPair::verify_weak(
					&signature,
					&serde_json::to_string(&addresses)
						.map(|s| s.into_bytes())
						.expect("address marshaling not to fail"),
					authority_pub_key,
				) {
					for address in addresses.iter() {
						// TODO: Why does add_reserved_peer take a string?
						// TODO: Remove unwrap.
						network_service.add_reserved_peer(address.to_string()).expect("adding reserved peer not to fail");
					}
				} else {
					// TODO: Log, don't print.
					println!("==== signature not valid");
				}
			} else {
				println!("==== Did not find a match for the key");
			}
		}
	}
}
