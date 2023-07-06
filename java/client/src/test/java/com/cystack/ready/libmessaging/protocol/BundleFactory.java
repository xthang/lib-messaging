package com.cystack.ready.libmessaging.protocol;

import com.cystack.ready.libmessaging.protocol.state.PreKeyBundle;
import com.cystack.ready.libmessaging.protocol.state.SignalProtocolStore;

public interface BundleFactory {
  PreKeyBundle createBundle(SignalProtocolStore store) throws InvalidKeyException;
}
