//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package com.cystack.ready.libmessaging.zkgroup;

import org.junit.Test;
import junit.framework.TestCase;
import com.cystack.ready.libmessaging.internal.Native;
import com.cystack.ready.libmessaging.protocol.util.Hex;
import com.cystack.ready.libmessaging.zkgroup.internal.*;

public final class NativeErrorsTest extends TestCase {

  @Test
  public void testBadNativeCalls() {
    byte[] params = new byte[10]; // invalid size
    byte[] uid = new byte[16]; // valid size
    boolean failed = false;
    try {
        Native.GroupSecretParams_DecryptUuid(params, uid);
        failed = true;
    } catch (AssertionError e) {}
    if (failed) {
        throw new AssertionError("Deserialization failure should Assert if CheckValidContents should have caught this");
    }

    byte[] temp = new byte[1]; // wrong length
    try {
        Native.ServerSecretParams_GenerateDeterministic(temp);
        throw new AssertionError("Failed to catch wrong byte array length");
    } catch (IllegalArgumentException e) {}
  }

}
