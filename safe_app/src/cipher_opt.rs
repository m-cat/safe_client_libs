// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Cipher options.

use client::AppClient;
use errors::AppError;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use safe_core::Client;
use safe_crypto::{Nonce, PublicEncryptKey};
use AppContext;

/// Cipher Options.
#[derive(Debug)]
pub enum CipherOpt {
    /// No encryption.
    PlainText,
    /// Encrypt using symmetric keys (usually for private data).
    Symmetric,
    /// Encrypt using asymmetric encryption (encrypting for peer to read).
    Asymmetric {
        /// PublicKey of the peer to whom we want to encrypt.
        peer_encrypt_key: PublicEncryptKey,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum WireFormat {
    Plain(Vec<u8>),
    Symmetric(Vec<u8>),
    Asymmetric(Vec<u8>),
}

impl CipherOpt {
    /// Encrypt plain text.
    pub fn encrypt(&self, plain_text: &[u8], app_ctx: &AppContext) -> Result<Vec<u8>, AppError> {
        match *self {
            CipherOpt::PlainText => Ok(serialise(&WireFormat::Plain(plain_text.to_owned()))?),
            CipherOpt::Symmetric => {
                let nonce = Nonce::new();
                let cipher_text = app_ctx
                    .sym_enc_key()?
                    .encrypt_bytes_with_nonce(plain_text, &nonce)?;
                let wire_format = WireFormat::Symmetric(cipher_text);

                Ok(serialise(&wire_format)?)
            }
            CipherOpt::Asymmetric {
                ref peer_encrypt_key,
            } => {
                let cipher_text = peer_encrypt_key.anonymously_encrypt_bytes(plain_text);
                Ok(serialise(&WireFormat::Asymmetric(cipher_text))?)
            }
        }
    }

    /// Decrypt something encrypted by CipherOpt::encrypt().
    pub fn decrypt(
        cipher_text: &[u8],
        app_ctx: &AppContext,
        client: &AppClient,
    ) -> Result<Vec<u8>, AppError> {
        if cipher_text.is_empty() {
            return Ok(Vec::new());
        }

        match deserialise::<WireFormat>(cipher_text)? {
            WireFormat::Plain(plain_text) => Ok(plain_text),
            WireFormat::Symmetric(cipher_text) => {
                Ok(app_ctx.sym_enc_key()?.decrypt_bytes(&cipher_text)?)
            }
            WireFormat::Asymmetric(cipher_text) => {
                let (asym_pk, asym_sk) = client
                    .encryption_keypair()
                    .ok_or(AppError::UnregisteredClientAccess)?;
                Ok(asym_sk.anonymously_decrypt_bytes(&cipher_text, &asym_pk)?)
            }
        }
    }
}
