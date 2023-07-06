//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// use std::convert::TryInto;

// use sha2::digest::FixedOutput;
// use typenum::Unsigned;
use subtle::ConstantTimeEq;

use lib_messaging_bridge_macros::*;
// use lib_messaging_protocol::incremental_mac::{calculate_chunk_size, Incremental, Validating};
use lib_messaging_protocol::crypto::{hmac_sha256};
use messaging_crypto::*;

// use crate::support::*;
use crate::*;

type Digest = sha2::Sha256;

///////////////////////////////////////////////////////////////////

#[bridge_fn(ffi = "compute_mac")]
fn Mac_Compute(mac_key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    // if mac_key.len() != 32 {
    //     return Err(Error::InvalidKeySize);
    // }

    Ok(hmac_sha256(mac_key, data))
}

#[bridge_fn(ffi = "verify_mac")]
fn Mac_Verify(mac_key: &[u8], data: &[u8], their_mac: &[u8], length: usize) -> Result<bool> {
    // if mac_key.len() != 32 {
    //     return Err(Error::InvalidKeySize);
    // }

    let our_mac = &Mac_Compute(mac_key, data)?[0..length];
    if our_mac.len() != length || their_mac.len() != length {
        return Err(Error::InvalidKeySize);
    }

    let result: bool = our_mac.ct_eq(their_mac).into();
    if !result {
        // A warning instead of an error because we try multiple sessions.
        log::warn!(
            "Bad Mac! Their Mac: {} Our Mac: {}",
            hex::encode(their_mac),
            hex::encode(our_mac)
        );
    }
    Ok(result)
}

///////////////////////////////////////////////////////////////////

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic]
    fn drop_without_finalize() {
        let incremental = IncrementalMac_Initialize(&[], 32);
        std::mem::drop(incremental);
    }

    #[test]
    fn drop_with_finalize() {
        let mut incremental = IncrementalMac_Initialize(&[], 32);
        IncrementalMac_Finalize(&mut incremental);
        std::mem::drop(incremental);
    }
}
