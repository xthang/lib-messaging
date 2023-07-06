package com.cystack.ready.libmessaging.protocol;

import com.cystack.ready.libmessaging.protocol.InvalidKeyIdException;
import com.cystack.ready.libmessaging.protocol.state.SignedPreKeyRecord;

public class TestNoSignedPreKeysStore extends TestInMemorySignalProtocolStore {
  @Override
  public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
    throw new InvalidKeyIdException("TestNoSignedPreKeysStore rejected loading " + signedPreKeyId);
  }
}
