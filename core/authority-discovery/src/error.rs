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

//! Authority discovery errors.

/// AuthorityDiscovery Result.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, derive_more::Display, derive_more::From)]
pub enum Error {
    RetrievingPublicKey,
    VerifyingDhtPayload,
    /// The authority-discovery runtime api does not guarantee atomicity in
    /// between calls. This can be problematic when the underlying cryptography
    /// key changes between a call to `public_key` and `sign`. In this scenario
    /// the retrieved public key does not correspond to the latter retrieved
    /// signature. Instead of allowing atomic operations one can make sure that
    /// pubic key and signature match in third step.
    // TODO: How about having `sign` return the public key as well.
    MissmatchingPublicKeyAndSignature,
    HashingPublicKey(libp2p::core::multiaddr::multihash::EncodeError),
    CallingRuntime(client::error::Error),
    SigningDhtPayload,
    /// From the Dht we only get the hashed public key of an authority. In
    /// order to retrieve the actual public key and to ensure it is actually
    /// an authority, we match the hash against the hash of the public keys
    /// of all other authorities. This error is the result of the above failing.
    MatchingHashedPublicKeyWithPublicKey,
	SettingPeersetPriorityGroup(String),
	Encoding(prost::EncodeError),
	Decoding(prost::DecodeError),
    ParsingMultiaddress(libp2p::core::multiaddr::Error),
}
