// Copyright 2022 Risc0, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use sha2::{Digest, Sha256};

use zkvm_host::{Prover, Receipt, Result};
use zkvm_serde::{from_slice, to_vec};

pub use digital_signature_core::{Message, Passphrase, SignMessageCommit, SigningRequest};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RawSignatureWithReceipt {
    pub journal: Vec<u8>,
    pub seal: Vec<u32>,
}

pub struct SignatureWithReceipt {
    receipt: Receipt,
}

impl SignatureWithReceipt {
    pub fn from_raw(raw: &RawSignatureWithReceipt) -> Result<SignatureWithReceipt> {
        let receipt = Receipt::from_raw(&raw.journal, &raw.seal).unwrap();
        Ok(SignatureWithReceipt { receipt: receipt })
    }

    pub fn to_raw(&self) -> Result<RawSignatureWithReceipt> {
        let receipt_journal = self.receipt.get_journal().unwrap();
        let receipt_seal = self.receipt.get_seal().unwrap();
        Ok(RawSignatureWithReceipt {
            journal: receipt_journal.to_vec(),
            seal: receipt_seal.to_vec(),
        })
    }

    pub fn get_commit(&self) -> Result<SignMessageCommit> {
        let msg = self.receipt.get_journal_vec()?;
        Ok(from_slice(msg.as_slice()).unwrap())
    }

    pub fn get_identity(&self) -> Result<zkvm_core::Digest> {
        let commit = self.get_commit().unwrap();
        Ok(commit.identity)
    }

    pub fn get_message(&self) -> Result<Message> {
        let commit = self.get_commit().unwrap();
        Ok(commit.msg)
    }

    pub fn verify(&self) -> Result<SignMessageCommit> {
        self.receipt
            .verify("examples/rust/digital_signature/core/sign")?;
        self.get_commit()
    }
}

pub fn sign(pass_str: impl AsRef<[u8]>, msg_str: impl AsRef<[u8]>) -> Result<SignatureWithReceipt> {
    let mut pass_hasher = Sha256::new();
    pass_hasher.update(pass_str);
    let mut pass_hash = [0u8; 32];
    pass_hash.copy_from_slice(&pass_hasher.finalize());

    let mut msg_hasher = Sha256::new();
    msg_hasher.update(msg_str);
    let mut msg_hash = [0u8; 32];
    msg_hash.copy_from_slice(&msg_hasher.finalize());

    let pass = Passphrase { pass: pass_hash };
    let msg = Message { msg: msg_hash };

    let params = SigningRequest {
        passphrase: pass,
        msg: msg,
    };
    let mut prover = Prover::new("examples/rust/digital_signature/core/sign")?;
    let vec = to_vec(&params).unwrap();
    prover.add_input(vec.as_slice())?;
    let receipt = prover.run()?;
    Ok(SignatureWithReceipt { receipt })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol() {
        let pass_str = "passphr4ase";
        let msg_str = "This message was signed by me";
        let signing_receipt = sign(pass_str, msg_str).unwrap();

        // Verify the receipt
        signing_receipt.verify().unwrap();

        // Verify the message hash
        let mut msg_hasher = Sha256::new();
        msg_hasher.update(msg_str);
        let mut msg_hash = [0u8; 32];
        msg_hash.copy_from_slice(&msg_hasher.finalize());
        assert_eq!(msg_hash, signing_receipt.get_message().unwrap().msg);

        // Verify the serialize/deserialize
        // let serialized_signing_receipt = bincode::serialize(&signing_receipt).unwrap();
        // let deserialized_receipt = bincode::deserialize(&serialized_signing_receipt).unwrap();
        let serialized_signing_receipt = serde_json::to_string(&signing_receipt)?;
        let deserialized_receipt = serde_json::from_str(&serialized_signing_receipt)?;
        deserialized_receipt.verify().unwrap();

        assert_eq!(
            deserialized_receipt.to_raw().unwrap(),
            signing_receipt.to_raw().unwrap()
        );

        log::info!("msg: {:?}", &msg_str);
        log::info!("commit: {:?}", &signing_receipt.get_commit().unwrap());
    }
}
