/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 * <p>
 * Licensed according to the LICENSE file in this repository.
 */
package com.cystack.ready.libmessaging.protocol.logging;

import android.util.Log;
import android.util.SparseIntArray;

public class AndroidMessagingProtocolLogger implements MessagingProtocolLogger {

	private static final SparseIntArray PRIORITY_MAP = new SparseIntArray(5) {{
		put(MessagingProtocolLogger.INFO, Log.INFO);
		put(MessagingProtocolLogger.ASSERT, Log.ASSERT);
		put(MessagingProtocolLogger.DEBUG, Log.DEBUG);
		put(MessagingProtocolLogger.VERBOSE, Log.VERBOSE);
		put(MessagingProtocolLogger.WARN, Log.WARN);

	}};

	@Override
	public void log(int priority, String tag, String message) {
		int androidPriority = PRIORITY_MAP.get(priority, Log.WARN);
		Log.println(androidPriority, tag, message);
	}
}
