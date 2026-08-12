// SPDX-License-Identifier: Apache-2.0
//! `BundleVerifier` implementation backed by yaml-sigil-verification.

use apf_types::{BundleVerifier, VerifyError};
use yaml_sigil_verification::{
    PreVerifyOutcome, PublicKeys, VerifierOptions, VerifierState, pre_verify_yaml,
    verify_from_pre_verify_yaml,
};

use crate::TrustStore;

pub struct YamlSigilVerifier {
    trust_store: TrustStore,
}

impl YamlSigilVerifier {
    pub fn new(trust_store: TrustStore) -> Self {
        Self { trust_store }
    }
}

impl BundleVerifier for YamlSigilVerifier {
    fn verify(&self, artifact: &[u8]) -> Result<Vec<u8>, VerifyError> {
        let pre = pre_verify_yaml(artifact, false);
        if pre.outcome != PreVerifyOutcome::Ok {
            return Err(VerifyError::Verify(
                "malformed or unsigned bundle artifact".into(),
            ));
        }

        let keyid = pre
            .unverified_signature
            .as_ref()
            .and_then(|s| s.keyid.clone())
            .ok_or_else(|| VerifyError::Verify("signature carrier has no keyid".into()))?;

        let (ed25519_key, p256_key) = self.trust_store.resolve_keys(&keyid);
        if ed25519_key.is_none() && p256_key.is_none() {
            return Err(VerifyError::Verify(format!(
                "trust_root_unknown: {keyid} (loaded: {:?})",
                self.trust_store.known_ids()
            )));
        }

        let keys = PublicKeys {
            ed25519: ed25519_key,
            p256: p256_key,
        };

        match verify_from_pre_verify_yaml(&pre, &keys, VerifierOptions::default()) {
            Ok(VerifierState::Verified { .. }) => Ok(pre
                .unverified_payload_bytes
                .expect("Ok pre-verify outcome has payload bytes")),
            Ok(VerifierState::Unsigned) => Err(VerifyError::Verify(
                "artifact has no signing attempt".into(),
            )),
            Ok(VerifierState::MalformedAttemptedSigned) => {
                Err(VerifyError::Verify("malformed signing attempt".into()))
            }
            Ok(VerifierState::SignedButAlgorithmUnsupported { algorithm }) => Err(
                VerifyError::Verify(format!("unsupported algorithm {algorithm:?}")),
            ),
            Ok(VerifierState::SignedButFailedVerification) => Err(VerifyError::Verify(
                "cryptographic verification failed".into(),
            )),
            Err(e) => Err(VerifyError::Verify(e.to_string())),
        }
    }
}
