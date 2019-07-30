// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::vault::{self, Vault, VaultGuard};
use crate::config_handler::{get_config, Config};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use maidsafe_utilities::thread;
use routing::{
    Authority, BootstrapConfig, Event, FullId, InterfaceError, Request, Response, RoutingError,
};
use safe_nd::{
    AppFullId, ClientFullId, ClientPublicId, Coins, Message, MessageId, PublicId, PublicKey,
    Request as RpcRequest, Response as RpcResponse, Signature, XorName,
};
#[cfg(any(feature = "testing", test))]
use safe_nd::{Error, Request as SndRequest, Response as SndResponse};
use std;
use std::cell::Cell;
use std::env;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Function that is used to tap into routing requests and return preconditioned responses.
pub type RequestHookFn = FnMut(&Request) -> Option<Response> + 'static;
pub type RequestHookFnNew = FnMut(&RpcRequest) -> Option<RpcResponse> + 'static;

/// Function that is used to modify responses before they are sent.
pub type ResponseHookFn = FnMut(Response) -> Response + 'static;
pub type ResponseHookFnNew = FnMut(RpcResponse) -> RpcResponse + 'static;

const CONNECT_THREAD_NAME: &str = "Mock routing connect";
const DELAY_THREAD_NAME: &str = "Mock routing delay";

const DEFAULT_DELAY_MS: u64 = 0;
const CONNECT_DELAY_MS: u64 = DEFAULT_DELAY_MS;

lazy_static! {
    static ref VAULT: Arc<Mutex<Vault>> = Arc::new(Mutex::new(Vault::new(get_config())));
}

/// Helper macro to receive a routing event and assert it's a response
/// success.
#[macro_export]
macro_rules! expect_success {
    ($rx:expr, $msg_id:expr, $res:path) => {
        match unwrap!($rx.recv_timeout(Duration::from_secs(10))) {
            Event::Response {
                response: $res { res, msg_id },
                ..
            } => {
                assert_eq!(msg_id, $msg_id);

                match res {
                    Ok(value) => value,
                    Err(err) => panic!("Unexpected error {:?}", err),
                }
            }
            event => panic!("Unexpected event {:?}", event),
        }
    };
}

/// Creates a thread-safe reference-counted pointer to the global vault.
pub fn clone_vault() -> Arc<Mutex<Vault>> {
    VAULT.clone()
}

pub fn unlimited_muts(config: &Config) -> bool {
    match env::var("SAFE_MOCK_UNLIMITED_MUTATIONS") {
        Ok(_) => true,
        Err(_) => match config.dev {
            Some(ref dev) => dev.mock_unlimited_mutations,
            None => false,
        },
    }
}

/// Mock routing implementation that mirrors the behaviour
/// of the real network but is not connected to it
pub struct Routing {
    vault: Arc<Mutex<Vault>>,
    sender: Sender<Event>,
    /// mock_routing::FullId for old types
    pub full_id: FullId,
    /// NewFullId for new types
    pub public_id: PublicId,
    max_ops_countdown: Option<Cell<u64>>,
    timeout_simulation: bool,
    request_hook: Option<Box<RequestHookFn>>,
    /// Temporary hook for the new safe_nd::Request
    pub request_hook_new: Option<Box<RequestHookFnNew>>,
    response_hook: Option<Box<ResponseHookFn>>,
    /// Temporary hook for the new safe_nd::Response
    pub response_hook_new: Option<Box<ResponseHookFnNew>>,
}

/// An enum representing the Full Id variants for a Client or App
pub enum NewFullId {
    /// Represents an application authorised by a client.
    App(AppFullId),
    /// Represents a network client.
    Client(ClientFullId),
}

impl NewFullId {
    /// Signs a given message using the App / Client full id as required
    pub fn sign(&self, msg: &[u8]) -> Signature {
        match self {
            NewFullId::App(app_full_id) => app_full_id.sign(msg),
            NewFullId::Client(client_full_id) => client_full_id.sign(msg),
        }
    }
}

impl Routing {
    /// Initialises mock routing.
    /// The function signature mirrors `routing::Client`.
    pub fn new(
        sender: Sender<Event>,
        id: Option<FullId>,
        public_id: PublicId,
        _bootstrap_config: Option<BootstrapConfig>,
        _msg_expiry_dur: Duration,
    ) -> Result<Self, RoutingError> {
        let _ = ::rust_sodium::init();

        let cloned_sender = sender.clone();
        let _ = thread::named(CONNECT_THREAD_NAME, move || {
            std::thread::sleep(Duration::from_millis(CONNECT_DELAY_MS));
            let _ = cloned_sender.send(Event::Connected);
        });

        Ok(Routing {
            vault: clone_vault(),
            sender,
            full_id: id.unwrap_or_else(FullId::new),
            public_id,
            max_ops_countdown: None,
            timeout_simulation: false,
            request_hook: None,
            request_hook_new: None,
            response_hook: None,
            response_hook_new: None,
        })
    }

    /// Send a routing message
    pub fn send(
        &mut self,
        requester: Option<PublicKey>,
        payload: &[u8],
    ) -> Result<(), InterfaceError> {
        let msg: Message = {
            let public_id = match requester {
                Some(public_key) => {
                    PublicId::Client(ClientPublicId::new(public_key.into(), public_key))
                }
                None => self.public_id.clone(),
            };
            let mut vault = self.lock_vault(true);
            unwrap!(vault.process_request(public_id, payload.to_vec()))
        };
        // Send response back to a client
        let (message_id, response) = if let Message::Response {
            message_id,
            response,
        } = msg
        {
            (message_id, response)
        } else {
            return Err(InterfaceError::InvalidState);
        };
        let response = Response::RpcResponse {
            res: Ok(unwrap!(serialise(&response))),
            msg_id: message_id,
        };
        // Use dummy authority for now
        let dummy_authority = Authority::ClientManager(new_rand::random());
        self.send_response(DEFAULT_DELAY_MS, dummy_authority, dummy_authority, response);

        Ok(())
    }

    /// Send a request and get a response
    pub fn req(
        &mut self,
        rx: &Receiver<Event>,
        request: RpcRequest,
        full_id_new: &NewFullId,
    ) -> RpcResponse {
        let message_id = MessageId::new();
        let signature = full_id_new.sign(&unwrap!(bincode::serialize(&(&request, message_id))));
        unwrap!(self.send(
            None,
            &unwrap!(serialise(&Message::Request {
                request,
                message_id,
                signature: Some(signature),
            }))
        ));
        let response = expect_success!(rx, message_id, Response::RpcResponse);
        unwrap!(deserialise(&response))
    }

    /// Send a request and get a response
    pub fn req_as_client(
        &mut self,
        rx: &Receiver<Event>,
        request: RpcRequest,
        client_full_id: &ClientFullId,
    ) -> RpcResponse {
        let message_id = MessageId::new();
        let signature = client_full_id.sign(&unwrap!(bincode::serialize(&(&request, message_id))));
        unwrap!(self.send(
            None,
            &unwrap!(serialise(&Message::Request {
                request,
                message_id,
                signature: Some(signature),
            }))
        ));
        let response = expect_success!(rx, message_id, Response::RpcResponse);
        unwrap!(deserialise(&response))
    }

    /// Sets the vault for this routing instance.
    pub fn set_vault(&mut self, vault: &Arc<Mutex<Vault>>) {
        self.vault = Arc::clone(vault);
    }

    fn send_response(
        &mut self,
        delay_ms: u64,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        mut response: Response,
    ) {
        if let Some(ref mut hook) = self.response_hook {
            response = hook(response);
        }

        let event = Event::Response { response, src, dst };

        self.send_event(delay_ms, event)
    }

    fn send_event(&self, delay_ms: u64, event: Event) {
        if delay_ms > 0 {
            let sender = self.sender.clone();
            let _ = thread::named(DELAY_THREAD_NAME, move || {
                std::thread::sleep(Duration::from_millis(delay_ms));
                if let Err(err) = sender.send(event) {
                    error!("mpsc-send failure: {:?}", err);
                }
            });
        } else if let Err(err) = self.sender.send(event) {
            error!("mpsc-send failure: {:?}", err);
        }
    }

    fn lock_vault(&self, write: bool) -> VaultGuard {
        vault::lock(&self.vault, write)
    }

    /// Returns the default boostrap config.
    pub fn bootstrap_config() -> Result<BootstrapConfig, InterfaceError> {
        Ok(BootstrapConfig::default())
    }

    /// Returns the config settings.
    pub fn config(&self) -> Config {
        let vault = self.lock_vault(false);
        vault.config()
    }

    /// Create coin balance in the mock network arbitrarily.
    pub fn create_balance(&self, owner: PublicKey, amount: Coins) {
        let mut vault = self.lock_vault(true);
        vault.mock_create_balance(&owner.into(), amount, owner);
    }
}

#[cfg(any(feature = "testing", test))]
impl Routing {
    /// Set hook function to override response before request is processed, for test purposes.
    pub fn set_request_hook<F>(&mut self, hook: F)
    where
        F: FnMut(&Request) -> Option<Response> + 'static,
    {
        let hook: Box<RequestHookFn> = Box::new(hook);
        self.request_hook = Some(hook);
    }

    /// Set hook function to override response before request is processed, for test purposes.
    pub fn set_request_hook_new<F>(&mut self, hook: F)
    where
        F: FnMut(&SndRequest) -> Option<SndResponse> + 'static,
    {
        let hook: Box<RequestHookFnNew> = Box::new(hook);
        self.request_hook_new = Some(hook);
    }

    /// Set hook function to override response after request is processed, for test purposes.
    pub fn set_response_hook<F>(&mut self, hook: F)
    where
        F: FnMut(Response) -> Response + 'static,
    {
        let hook: Box<ResponseHookFn> = Box::new(hook);
        self.response_hook = Some(hook);
    }

    /// Set hook function to override response after request is processed, for test purposes.
    pub fn set_response_hook_new<F>(&mut self, hook: F)
    where
        F: FnMut(SndResponse) -> SndResponse + 'static,
    {
        let hook: Box<ResponseHookFnNew> = Box::new(hook);
        self.response_hook_new = Some(hook);
    }

    /// Removes hook function to override response results
    pub fn remove_request_hook(&mut self) {
        self.request_hook = None;
    }

    /// Sets a maximum number of operations
    pub fn set_network_limits(&mut self, max_ops_count: Option<u64>) {
        self.max_ops_countdown = max_ops_count.map(Cell::new)
    }

    /// Simulates network disconnect
    pub fn simulate_disconnect(&self) {
        let sender = self.sender.clone();
        let _ = std::thread::spawn(move || unwrap!(sender.send(Event::Terminate)));
    }

    /// Simulates network timeouts
    pub fn set_simulate_timeout(&mut self, enable: bool) {
        self.timeout_simulation = enable;
    }

    /// Add some coins to a wallet's PublicKey
    pub fn allocate_test_coins(
        &self,
        coin_balance_name: &XorName,
        amount: Coins,
    ) -> Result<(), Error> {
        let mut vault = self.lock_vault(true);
        vault.mock_increment_balance(coin_balance_name, amount)
    }
}

impl Drop for Routing {
    fn drop(&mut self) {
        let _ = self.sender.send(Event::Terminate);
    }
}
