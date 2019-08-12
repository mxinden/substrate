#![warn(missing_docs)]

//! Substrate validator discovery.
//!
//! This crate enables Substrate validators to directly connect to other
//! validators. [`ValidatorDiscovery`] implements the Future trait. By polling
//! a [`ValidatorDiscovery`] a validator:
//!
//!
//! 1. **Makes itself discoverable**
//!
//!    1. Retrieves its external addresses.
//!
//!    2. Adds its network peer id to the addresses.
//!
//!    3. Signs the above.
//!
//!    4. Puts the signature and the addresses on the libp2p Kademlia DHT.
//!
//!
//! 2. **Discovers other validators**
//!
//!    1. Retrieves the current set of authorities..
//!
//!    2. Starts DHT queries for the ids of the authorities.
//!
//!    3. Validates the signatures of the retrieved key value pairs.
//!
//!    4. Adds the retrieved external addresses as priority nodes to the
//!    peerset.

use std::sync::Arc;

use client::blockchain::HeaderBackend;
use consensus_common_primitives::ImOnlineApi;
use error::{Error, Result};
use futures::{prelude::*, sync::mpsc::UnboundedReceiver};
use log::error;
use network::specialization::NetworkSpecialization;
use network::{DhtEvent, ExHashT, NetworkStateInfo};
use sr_primitives::generic::BlockId;
use sr_primitives::traits::Block;
use sr_primitives::traits::ProvideRuntimeApi;
use std::marker::PhantomData;
use std::time::Duration;

// TODO: Needed?
mod error;

/// A ValidatorDiscovery makes a given validator discoverable as well as
/// discovers other validators.
pub struct ValidatorDiscovery<AuthorityId, Client, B, S, H>
where
    B: Block + 'static,
    S: NetworkSpecialization<B>,
    H: ExHashT,
    AuthorityId:
        std::string::ToString + codec::Codec + std::convert::AsRef<[u8]> + std::clone::Clone,
    Client: ProvideRuntimeApi + Send + Sync + 'static + HeaderBackend<B>,
    <Client as ProvideRuntimeApi>::Api: ImOnlineApi<B, AuthorityId>,
{
    client: Arc<Client>,

    network: Arc<network::NetworkService<B, S, H>>,
    dht_event_rx: UnboundedReceiver<DhtEvent>,

    /// Interval to be proactive on, e.g. publishing own addresses or starting
    /// to query for addresses.
    interval: tokio_timer::Interval,

    phantom_authority_id: PhantomData<AuthorityId>,
}

impl<AuthorityId, Client, B, S, H> ValidatorDiscovery<AuthorityId, Client, B, S, H>
where
    B: Block + 'static,
    S: NetworkSpecialization<B>,
    H: ExHashT,
    AuthorityId:
        std::string::ToString + codec::Codec + std::convert::AsRef<[u8]> + std::clone::Clone,
    Client: ProvideRuntimeApi + Send + Sync + 'static + HeaderBackend<B>,
    <Client as ProvideRuntimeApi>::Api: ImOnlineApi<B, AuthorityId>,
{
    /// Return a new validator discovery.
    pub fn new(
        client: Arc<Client>,
        network: Arc<network::NetworkService<B, S, H>>,
        dht_event_rx: futures::sync::mpsc::UnboundedReceiver<DhtEvent>,
    ) -> ValidatorDiscovery<AuthorityId, Client, B, S, H> {
        let interval = tokio_timer::Interval::new_interval(Duration::from_secs(5));

        ValidatorDiscovery {
            client,
            network,
            dht_event_rx,
            interval,
            phantom_authority_id: PhantomData,
        }
    }

    fn publish_own_ext_addresses(&mut self) -> Result<()> {
        let id = BlockId::hash(self.client.info().best_hash);
        let pub_key = self
            .client
            .runtime_api()
            .public_key(&id)
            .map_err(|_x| Error::CallingRuntime)?
            .ok_or(Error::RetrievingPublicKey)?;

        let hashed_public_key =
            libp2p::multihash::encode(libp2p::multihash::Hash::SHA2256, pub_key.as_ref())
                .expect("public key hashing not to fail");

        let addresses: Vec<libp2p::Multiaddr> = self
            .network
            .external_addresses()
            .iter()
            .map(|a| {
                let mut a = a.clone();
                a.push(libp2p::core::multiaddr::Protocol::P2p(
                    self.network.peer_id().into(),
                ));
                a
            })
            .collect();

        let serialized_addresses = serde_json::to_string(&addresses)
            .map(|s| s.into_bytes())
            .expect("enriched_address marshaling not to fail");

        let sig = self
            .client
            .runtime_api()
            .sign(&id, serialized_addresses)
            .unwrap()
            .unwrap();

        // TODO: Could sig also derive serialize instead of `as_ref().to_vec()`?
        let payload =
            serde_json::to_string(&(addresses, sig)).expect("payload marshaling not to fail");

        self.network
            .put_value(hashed_public_key, payload.into_bytes());

        Ok(())
    }

    fn request_addresses_of_others(&mut self) {
        let id = BlockId::hash(self.client.info().best_hash);
        let authorities = self.client.runtime_api().authorities(&id).unwrap();

        for authority in authorities.iter() {
            let hashed_public_key =
                libp2p::multihash::encode(libp2p::multihash::Hash::SHA2256, authority.as_ref())
                    .expect("public key hashing not to fail");

            self.network.get_value(&hashed_public_key.clone());
        }
    }

    fn handle_dht_events(&mut self) {
        while let Ok(Async::Ready(Some(event))) = self.dht_event_rx.poll() {
            match event {
                DhtEvent::ValueFound(v) => {
                    self.handle_dht_value_found_event(v);
                }
                // TODO: We should log this!?
                DhtEvent::ValueNotFound(_hash) => println!("Did not find a value"),
                DhtEvent::ValuePut(_hash) => println!("Succesfully put a value"),
                // TODO: We should log this!?
                DhtEvent::ValuePutFailed(_hash) => println!("put failed"),
            }
        }
    }

    fn handle_dht_value_found_event(
        &mut self,
        values: Vec<(libp2p::multihash::Multihash, Vec<u8>)>,
    ) {
        let id = BlockId::hash(self.client.info().best_hash);
        let authorities = self.client.runtime_api().authorities(&id);

        let valid_authority = |a: &libp2p::multihash::Multihash| -> Option<AuthorityId> {
            match &authorities {
                Ok(authorities) => {
                    for authority in authorities.iter() {
                        let hashed_public_key = libp2p::multihash::encode(
                            libp2p::multihash::Hash::SHA2256,
                            authority.to_string().as_bytes(),
                        )
                        .expect("public key hashing not to fail");

                        // TODO: Comparing two pointers is safe, right? Given they are not fat-pointers.
                        if a == &hashed_public_key {
                            return Some(authority.clone());
                        }
                    }
                }
                // TODO: Should we handle the error here?
                Err(_e) => {}
            }

            return None;
        };

        for (key, value) in values.iter() {
            // TODO: Should we log if it is not a valid one?
            if let Some(authority_pub_key) = valid_authority(key) {
                println!("===== adding other node");

                let (addresses, sig): (Vec<libp2p::Multiaddr>, Vec<u8>) =
                    serde_json::from_slice(value).expect("payload unmarshaling not to fail");

                let serialized_addresses = serde_json::to_string(&addresses)
                    .map(|s| s.into_bytes())
                    .expect("address marshaling not to fail");

                let authority_pub_key: AuthorityId = authority_pub_key;

                let valid = self
                    .client
                    .runtime_api()
                    .verify(
                        // TODO: Should we only get the id once?
                        &BlockId::hash(self.client.info().best_hash),
                        serialized_addresses,
                        sig,
                        authority_pub_key,
                    )
                    .expect("verify api call not to fail");

                // TODO: is using verify-weak a problem here?
                if valid {
                    for address in addresses.iter() {
                        // TODO: Why does add_reserved_peer take a string?
                        // TODO: Remove unwrap.
                        self.network
                            .add_reserved_peer(address.to_string())
                            .expect("adding reserved peer not to fail");
                    }
                } else {
                    println!("==== Did not find a match for the key");
                }
            }
        }
    }
}

impl<AuthorityId, Client, B, S, H> futures::Future
    for ValidatorDiscovery<AuthorityId, Client, B, S, H>
where
    B: Block + 'static,
    S: NetworkSpecialization<B>,
    H: ExHashT,
    AuthorityId:
        std::string::ToString + codec::Codec + std::convert::AsRef<[u8]> + std::clone::Clone,
    Client: ProvideRuntimeApi + Send + Sync + 'static + HeaderBackend<B>,
    <Client as ProvideRuntimeApi>::Api: ImOnlineApi<B, AuthorityId>,
{
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> futures::Poll<Self::Item, Self::Error> {
        let mut inner = || -> Result<()> {
            while let Ok(Async::Ready(_)) = self.interval.poll() {
                self.publish_own_ext_addresses()?;

                self.request_addresses_of_others();
            }

            self.handle_dht_events();

            Ok(())
        };

        match inner() {
            Ok(()) => {}
            Err(e) => error!(target: "sub-validator-discovery", "Poll failure: {:?}", e),
        }

        // Make sure to always return NotReady as this is a long running task
        // with the same lifetime of the node itself.
        Ok(futures::Async::NotReady)
    }
}
