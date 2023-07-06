package com.cystack.ready.libmessaging.metadata;


import com.cystack.ready.libmessaging.protocol.IdentityKey;
import com.cystack.ready.libmessaging.protocol.IdentityKeyPair;
import com.cystack.ready.libmessaging.protocol.ecc.Curve;
import com.cystack.ready.libmessaging.protocol.ecc.ECKeyPair;
import com.cystack.ready.libmessaging.protocol.state.SignedPreKeyRecord;
import com.cystack.ready.libmessaging.protocol.state.impl.InMemorySignalProtocolStore;
import com.cystack.ready.libmessaging.protocol.util.KeyHelper;

public class TestInMemorySignalProtocolStore extends InMemorySignalProtocolStore {
  public TestInMemorySignalProtocolStore() {
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