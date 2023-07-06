//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package com.cystack.ready.libmessaging.protocol;

import junit.framework.TestCase;
import com.cystack.ready.libmessaging.protocol.IdentityKey;
import com.cystack.ready.libmessaging.protocol.IdentityKeyPair;

public class IdentityKeyTest extends TestCase {
  public void testSignAlternateKey() {
    IdentityKeyPair primary = IdentityKeyPair.generate();
    IdentityKeyPair secondary = IdentityKeyPair.generate();
    byte[] signature = secondary.signAlternateIdentity(primary.getPublicKey());
    assertTrue(secondary.getPublicKey().verifyAlternateIdentity(primary.getPublicKey(), signature));
  }
}
