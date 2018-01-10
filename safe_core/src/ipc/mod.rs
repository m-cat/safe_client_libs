// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

/// Request module
pub mod req;
/// Response module
pub mod resp;

mod errors;

pub use self::errors::IpcError;
pub use self::req::{AppExchangeInfo, AuthReq, ContainersReq, IpcReq, Permission, ShareMData,
                    ShareMDataReq};
pub use self::resp::{AccessContInfo, AccessContainerEntry, AppKeys, AuthGranted, IpcResp,
                     access_container_enc_key};

use serde::Serialize;
use ffi_utils::{base64_decode, base64_encode};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use rand::{self, Rng};
pub use routing::BootstrapConfig;
use std::u32;
use std::hash::BuildHasher;

/// IPC message
#[cfg_attr(feature = "cargo-clippy", allow(large_enum_variant))]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum IpcMsg<S: BuildHasher> {
    /// Request
    Req {
        /// Request ID
        req_id: u32,
        /// Request
        req: IpcReq<S>,
    },
    /// Response
    Resp {
        /// Request ID
        req_id: u32,
        /// Response
        resp: IpcResp,
    },
    /// Revoked
    Revoked {
        /// Application ID
        app_id: String,
    },
    /// Generic error like couldn't parse IpcMsg etc.
    Err(IpcError),
}

/// Encode `IpcMsg` into string, using base64 encoding.
pub fn encode_msg<S: BuildHasher + Serialize>(msg: &IpcMsg<S>) -> Result<String, IpcError> {
    Ok(base64_encode(&serialise(msg)?))
}

/// Decode `IpcMsg` encoded with base64 encoding.
pub fn decode_msg<S: BuildHasher + Serialize>(encoded: &str) -> Result<IpcMsg<S>, IpcError> {
    Ok(deserialise(&base64_decode(encoded)?)?)
}

/// Generate unique request ID.
pub fn gen_req_id() -> u32 {
    // Generate the number in range 1..MAX inclusive.
    rand::thread_rng().gen_range(0, u32::MAX) + 1
}
