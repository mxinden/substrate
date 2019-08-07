#![warn(missing_docs)]

use std::sync::Arc;

use client::blockchain::HeaderBackend;
use consensus_common_primitives::ConsensusApi;
use error::{Error, Result};
use network::specialization::NetworkSpecialization;
use network::ExHashT;
use sr_primitives::generic::BlockId;
use sr_primitives::traits::Block;
use sr_primitives::traits::ProvideRuntimeApi;

mod error;

pub struct ValidatorDiscovery<Client, B, S, H>
where
    B: Block + 'static,
    S: NetworkSpecialization<B>,
    H: ExHashT,
{
    client: Arc<Client>,
    network: Arc<network::NetworkService<B, S, H>>,
}

impl<Client, B, S, H> ValidatorDiscovery<Client, B, S, H>
where
    B: Block + 'static,
    S: NetworkSpecialization<B>,
    H: ExHashT,
{
    pub fn new<AuthorityId>(
        client: Arc<Client>,
        network: Arc<network::NetworkService<B, S, H>>,
    ) -> Result<ValidatorDiscovery<Client, B, S, H>>
    where
        Client: ProvideRuntimeApi + Send + Sync + 'static + HeaderBackend<B>,
        <Client as ProvideRuntimeApi>::Api: ConsensusApi<B, AuthorityId>,
        AuthorityId: std::string::ToString + parity_codec::Codec,
    {
        let id = BlockId::hash( client.info().best_hash);
        client.runtime_api().authorities(&id);
        Ok(ValidatorDiscovery { network, client })
    }
}
