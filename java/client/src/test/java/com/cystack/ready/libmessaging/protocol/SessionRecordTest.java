//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package com.cystack.ready.libmessaging.protocol;

import junit.framework.TestCase;
import com.cystack.ready.libmessaging.protocol.state.SessionRecord;

public class SessionRecordTest extends TestCase {

  public void testUninitAccess() {
    SessionRecord empty_record = new SessionRecord();

    assertFalse(empty_record.hasSenderChain());

    assertEquals(empty_record.getSessionVersion(), 0);
  }
}
