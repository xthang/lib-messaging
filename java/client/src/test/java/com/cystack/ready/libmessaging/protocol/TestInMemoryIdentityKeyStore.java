package com.cystack.ready.libmessaging.protocol;

import com.cystack.ready.libmessaging.protocol.ecc.Curve;
import com.cystack.ready.libmessaging.protocol.ecc.ECKeyPair;
import com.cystack.ready.libmessaging.protocol.util.KeyHelper;

public class TestInMemoryIdentityKeyStore extends com.cystack.ready.libmessaging.protocol.state.impl.InMemoryIdentityKeyStore {
  public TestInMemoryIdentityKeyStore() {
    super(generateIdentityKeyPair(), generateRegistrationId());
  }

  private static IdentityKeyPair generateIdentityKeyPair() {
    ECKeyPair identityKeyPairKeys = Curve.generateKeyPair();

    return new IdentityKeyPair(new IdentityKey(identityKeyPairKeys.getPublicKey()),
                               identityKeyPairKeys.getPrivateKey());
  }

  private static int generateRegistrationId() {
    return KeyHelper.generateRegistrationId(false);
  }

}
