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

pub use digital_signature_proof::{Message, Passphrase, SignMessageCommit, SigningRequest};
use r0vm_host::{Proof, Prover, Result};
use r0vm_serde::{from_slice, to_vec};
use sha2::{Digest, Sha256};

pub struct SignatureWithReceipt {
    proof: Proof,
}

impl SignatureWithReceipt {
    pub fn of_raw(msg_raw: &[u8], core_raw: &[u32]) -> Result<SignatureWithReceipt> {
        let proof = Proof::of_raw(msg_raw, core_raw).unwrap();
        Ok(SignatureWithReceipt { proof: proof })
    }

    pub fn get_raw(&self) -> Result<(&[u8], &[u32])> {
        let proof_msg = self.proof.get_message().unwrap();
        let proof_core = self.proof.get_core().unwrap();
        Ok((proof_msg, proof_core))
    }

    pub fn get_commit(&self) -> Result<SignMessageCommit> {
        let msg = self.proof.get_message_vec()?;
        Ok(from_slice(msg.as_slice()).unwrap())
    }

    pub fn get_identity(&self) -> Result<r0vm_core::Digest> {
        let commit = self.get_commit().unwrap();
        Ok(commit.identity)
    }

    pub fn get_message(&self) -> Result<Message> {
        let commit = self.get_commit().unwrap();
        Ok(commit.msg)
    }

    pub fn verify(&self) -> Result<SignMessageCommit> {
        self.proof
            .verify("examples/rust/digital_signature/proof/sign")?;
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
    let mut prover = Prover::new("examples/rust/digital_signature/proof/sign")?;
    let vec = to_vec(&params).unwrap();
    prover.add_input(vec.as_slice())?;
    let proof = prover.run()?;
    Ok(SignatureWithReceipt { proof })
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
        let (msg_raw, core_raw) = signing_receipt.get_raw().unwrap();
        let deserialized_receipt = SignatureWithReceipt::of_raw(msg_raw, core_raw).unwrap();
        deserialized_receipt.verify().unwrap();

        assert_eq!(
            deserialized_receipt.get_raw().unwrap(),
            signing_receipt.get_raw().unwrap()
        );

        log::info!("msg: {:?}", &msg_str);
        log::info!("commit: {:?}", &signing_receipt.get_commit().unwrap());
    }
}
