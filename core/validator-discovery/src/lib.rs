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
use std::collections::HashMap;


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
            .map_err(Error::CallingRuntime)?
            .ok_or(Error::RetrievingPublicKey)?;

        let hashed_public_key =
            libp2p::multihash::encode(libp2p::multihash::Hash::SHA2256, pub_key.as_ref())
                .map_err(Error::HashingPublicKey)?;

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
            .map_err(Error::SerializingAddresses)?;

        let sig = self
            .client
            .runtime_api()
            .sign(&id, serialized_addresses)
            .map_err(Error::CallingRuntime)?
            .ok_or(Error::SigningDhtPayload)?;

        let payload =
            serde_json::to_string(&(addresses, sig)).map_err(Error::SerializingDhtPayload)?;

        self.network
            .put_value(hashed_public_key, payload.into_bytes());

        Ok(())
    }

    fn request_addresses_of_others(&mut self) -> Result<()> {
        let id = BlockId::hash(self.client.info().best_hash);
        let authorities = self
            .client
            .runtime_api()
            .authorities(&id)
            .map_err(Error::CallingRuntime)?;

        for authority in authorities.iter() {
            let hashed_public_key =
                libp2p::multihash::encode(libp2p::multihash::Hash::SHA2256, authority.as_ref())
                    .map_err(Error::HashingPublicKey)?;

            self.network.get_value(&hashed_public_key.clone());
        }

        Ok(())
    }

    fn handle_dht_events(&mut self) -> Result<()> {
        while let Ok(Async::Ready(Some(event))) = self.dht_event_rx.poll() {
            match event {
                DhtEvent::ValueFound(v) => {
                    self.handle_dht_value_found_event(v)?;
                }
                // TODO: We should log this!?
                DhtEvent::ValueNotFound(_hash) => println!("Did not find a value"),
                DhtEvent::ValuePut(_hash) => println!("Succesfully put a value"),
                // TODO: We should log this!?
                DhtEvent::ValuePutFailed(_hash) => println!("put failed"),
            }
        }

        Ok(())
    }

    fn handle_dht_value_found_event(
        &mut self,
        values: Vec<(libp2p::multihash::Multihash, Vec<u8>)>,
    ) -> Result<()> {
        let id = BlockId::hash(self.client.info().best_hash);

        // From the Dht we only get the hashed public key of an authority. In
        // order to retrieve the actual public key and to ensure it is actually
        // an authority, we match the hash against the hash of the public keys
        // of all other authorities.
        let authorities = self.client.runtime_api().authorities(&id)?;
        let authorities: HashMap<libp2p::multihash::Multihash, AuthorityId> =
            authorities
                .into_iter()
                .map(|a| {
                    libp2p::multihash::encode(
                        libp2p::multihash::Hash::SHA2256,
                        a.to_string().as_bytes(),
                    )
                    .map(|h| (h, a))
                    .map_err(Error::HashingPublicKey)
                })
            .collect::<Result<HashMap<libp2p::multihash::Multihash, AuthorityId>>>()?;

        for (key, value) in values.iter() {
            let authority_pub_key: &AuthorityId = authorities
                .get(key)
                .ok_or(Error::MatchingHashedPublicKeyWithPublicKey)?;

            let (addresses, sig): (Vec<libp2p::Multiaddr>, Vec<u8>) =
                serde_json::from_slice(value).map_err(Error::DeserializingDhtPayload)?;

            let serialized_addresses = serde_json::to_string(&addresses)
                .map(|s| s.into_bytes())
                .map_err(Error::SerializingAddresses)?;

            let is_verified = self
                .client
                .runtime_api()
                .verify(&id, serialized_addresses, sig, authority_pub_key.clone())
                .map_err(Error::CallingRuntime)?;

            if is_verified {
                for address in addresses.iter() {
                    // TODO: Why does add_reserved_peer take a string?
                    // TODO: Don't add as reserved peer, but as priority group.
                    self.network
                        .add_reserved_peer(address.to_string())
                        .map_err(Error::AddingReservedPeer)?;
                }
            } else {
                return Err(Error::VerifyingDhtPayload);
            }
        }

        Ok(())
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

                self.request_addresses_of_others()?;
            }

            self.handle_dht_events()?;

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
