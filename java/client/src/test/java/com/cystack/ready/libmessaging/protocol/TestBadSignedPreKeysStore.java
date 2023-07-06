package com.cystack.ready.libmessaging.protocol;

import com.cystack.ready.libmessaging.protocol.InvalidKeyIdException;
import com.cystack.ready.libmessaging.protocol.state.SignedPreKeyRecord;

public class TestBadSignedPreKeysStore extends TestInMemorySignalProtocolStore {
  public static class CustomException extends RuntimeException {
    CustomException(String message) {
      super(message);
    }
  }

  @Override
  public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
    throw new CustomException("TestBadSignedPreKeysStore rejected loading " + signedPreKeyId);
  }
}
