/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package com.cystack.ready.libmessaging.protocol.logging;

public class MessagingProtocolLoggerProvider {

  private static MessagingProtocolLogger provider;

  public static MessagingProtocolLogger getProvider() {
    return provider;
  }

  public static void setProvider(MessagingProtocolLogger provider) {
    MessagingProtocolLoggerProvider.provider = provider;
  }
}
