/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package com.cystack.ready.libmessaging.protocol;

public class InvalidKeyIdException extends Exception {
  public InvalidKeyIdException(String detailMessage) {
    super(detailMessage);
  }

  public InvalidKeyIdException(Throwable throwable) {
    super(throwable);
  }
}
