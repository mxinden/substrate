#![warn(missing_docs)]

///! TODO docs.

use std::sync::Arc;

use client::blockchain::HeaderBackend;
use consensus_common_primitives::ConsensusApi;
use error::{Error, Result};
use futures::{future::Executor, prelude::*, sync::mpsc};
use network::specialization::NetworkSpecialization;
use network::ExHashT;
use network::{DhtEvent, Event};
use sr_primitives::generic::BlockId;
use sr_primitives::traits::Block;
use sr_primitives::traits::ProvideRuntimeApi;
use std::marker::PhantomData;
use std::time::{Duration, Instant};

// TODO: Needed?
mod error;

pub struct ValidatorDiscovery<AuthorityId, Client, B, S, H>
where
    B: Block + 'static,
    S: NetworkSpecialization<B>,
    H: ExHashT,
    AuthorityId: std::string::ToString + codec::Codec,
    Client: ProvideRuntimeApi + Send + Sync + 'static + HeaderBackend<B>,
    <Client as ProvideRuntimeApi>::Api: ConsensusApi<B, AuthorityId>,
{
    client: Arc<Client>,

    network: Arc<network::NetworkService<B, S, H>>,
    dht_event_rx: futures::sync::mpsc::UnboundedReceiver<DhtEvent>,

    /// Interval to be proactive.
    interval: tokio_timer::Interval,

    keystore: keystore::KeyStorePtr,

    phantom: PhantomData<AuthorityId>,
}

impl<AuthorityId, Client, B, S, H> ValidatorDiscovery<AuthorityId, Client, B, S, H>
where
    B: Block + 'static,
    S: NetworkSpecialization<B>,
    H: ExHashT,
    AuthorityId: std::string::ToString + codec::Codec,
    Client: ProvideRuntimeApi + Send + Sync + 'static + HeaderBackend<B>,
    <Client as ProvideRuntimeApi>::Api: ConsensusApi<B, AuthorityId>,
{
    /// Return a new validator discovery.
    pub fn new(
        client: Arc<Client>,
        network: Arc<network::NetworkService<B, S, H>>,
        dht_event_rx: futures::sync::mpsc::UnboundedReceiver<DhtEvent>,
        keystore: keystore::KeyStorePtr,
    ) -> ValidatorDiscovery<AuthorityId, Client, B, S, H> {
        let mut interval = tokio_timer::Interval::new_interval(Duration::from_secs(5));

        ValidatorDiscovery {
            client,
            network,
            dht_event_rx,
            interval,
            keystore,
            phantom: PhantomData,
        }
    }

    pub fn publish_own_ext_addresses(&mut self) {
        // TODO: Don't just use babe crypto.
        let pub_key = self.keystore.read().public_keys_by_type::<babe_primitives::AuthorityId>(primitives::crypto::key_types::BABE);
        let key_pair = self.keystore.read().key_pair::<babe_primitives::AuthorityPair>(&pub_key.unwrap()[0]);




        let id = BlockId::hash(self.client.info().best_hash);
        self.client.runtime_api().authorities(&id);
    }
}

impl<AuthorityId, Client, B, S, H> futures::Future
    for ValidatorDiscovery<AuthorityId, Client, B, S, H>
where
    B: Block + 'static,
    S: NetworkSpecialization<B>,
    H: ExHashT,
    AuthorityId: std::string::ToString + codec::Codec,
    Client: ProvideRuntimeApi + Send + Sync + 'static + HeaderBackend<B>,
    <Client as ProvideRuntimeApi>::Api: ConsensusApi<B, AuthorityId>,
{
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> futures::Poll<Self::Item, Self::Error> {
        while let Ok(Async::Ready(_)) = self.interval.poll() {
            self.publish_own_ext_addresses();
        }

        Ok(futures::Async::NotReady)
    }
}


				// let id = BlockId::hash( client.info().chain.best_hash);

				// // Put our addresses on the DHT if we are a validator.
				// if let Some(authority_key) = authority_key_provider.authority_key( &id) {
				// 	let public_key = authority_key.public().to_string();

				// 	let hashed_public_key = libp2p::multihash::encode(
				// 		libp2p::multihash::Hash::SHA2256,
				// 		&public_key.as_bytes(),
				// 	).expect("public key hashing not to fail");

				// 	let addresses: Vec<Multiaddr> = network.service().external_addresses()
				// 		.iter()
				// 		.map(|a| {
				// 			let mut a = a.clone();
				// 			a.push(libp2p::core::multiaddr::Protocol::P2p(network.service().peer_id().into()));
				// 			a
				// 		})
				// 		.collect();
				// 	println!("==== external addresses: {:?}", addresses);

				// 	// TODO: Remove unwrap.
				// 	let signature = authority_key.sign(
				// 		&serde_json::to_string(&addresses)
				// 			.map(|s| s.into_bytes())
				// 			.expect("enriched_address marshaling not to fail")
				// 	).as_ref().to_vec();

				// 	// TODO: Remove unwrap.
				// 	let payload = serde_json::to_string(&(addresses, signature)).expect("payload marshaling not to fail");

				// 	network.service().put_value(hashed_public_key, payload.into_bytes());
				// }

				// // Query addresses of other validators.
				// // TODO: Should non-validators also do this? Probably not a good default.
				// match client.runtime_api().authorities(&id) {
				// 	Ok(authorities) => {
				// 		for authority in authorities.iter() {
				// 			println!("==== querying dht for authority: {}", authority.to_string());
				// 			// TODO: Remove unwrap.
				// 			let hashed_public_key = libp2p::multihash::encode(
				// 				libp2p::multihash::Hash::SHA2256,
				// 				authority.to_string().as_bytes(),
				// 			).expect("public key hashing not to fail");

				// 			network.service().get_value(&hashed_public_key.clone());
				// 		}
				// 	},
				// 	Err(e) => {
				// 		println!("==== Got no authorities, but an error: {:?}", e);
				// 	}
				// }





			// let authorities = client.runtime_api().authorities(&BlockId::hash(client.info().chain.best_hash));
			// let valid_authority = |a: &libp2p::multihash::Multihash| {
			// 	match &authorities {
			// 		Ok(authorities) => {
			// 			for authority in authorities.iter() {
			// 				let hashed_public_key = libp2p::multihash::encode(
			// 					libp2p::multihash::Hash::SHA2256,
			// 					authority.to_string().as_bytes(),
			// 				).expect("public key hashing not to fail");

			// 				// TODO: Comparing two pointers is safe, right? Given they are not fat-pointers.
			// 				if a == &hashed_public_key {
			// 					return Some(authority.clone());
			// 				}
			// 			}
			// 		},
			// 		// TODO: Should we handle the error here?
			// 		Err(_e) => {},
			// 	}

			// 	return None;
			// };

			// // TODO: Can we do this nicer?
			// let network_service = network.service().clone();
			// let add_reserved_peer = |values: Vec<(libp2p::multihash::Multihash, Vec<u8>)>| {
			// 	for (key, value) in values.iter() {
			// 		// TODO: Should we log if it is not a valid one?
			// 		if let Some(authority_pub_key) = valid_authority(key) {
			// 			println!("===== adding other node");

			// 			let (addresses, signature): (Vec<Multiaddr>, Vec<u8>) = serde_json::from_slice(value).expect("payload unmarshaling not to fail");

			// 			// TODO: is using verify-weak a problem here?
			// 			if <<C as Components>::Factory as ServiceFactory>::ConsensusPair::verify_weak(
			// 				&signature,
			// 				&serde_json::to_string(&addresses)
			// 					.map(|s| s.into_bytes())
			// 					.expect("address marshaling not to fail"),
			// 				authority_pub_key,
			// 			) {
			// 				for address in addresses.iter() {
			// 					// TODO: Why does add_reserved_peer take a string?
			// 					// TODO: Remove unwrap.
			// 					network_service.add_reserved_peer(address.to_string()).expect("adding reserved peer not to fail");
			// 				}
			// 			} else {
			// 				// TODO: Log, don't print.
			// 				println!("==== signature not valid");
			// 			}
			// 		} else {
			// 			println!("==== Did not find a match for the key");
			// 		}
			// 	}
			// };
