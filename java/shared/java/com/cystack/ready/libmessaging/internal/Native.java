//
// Copyright (C) 2023 Ready.io
//

// WARNING: this file was automatically generated

package com.cystack.ready.libmessaging.internal;

import com.cystack.ready.libmessaging.protocol.logging.Log;
import com.cystack.ready.libmessaging.protocol.logging.MessagingProtocolLogger;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.UUID;
import java.util.Map;

public final class Native {
  private static void copyToTempFileAndLoad(InputStream in, String name) throws IOException {
    File tempFile = Files.createTempFile(null, name).toFile();
    tempFile.deleteOnExit();

    try (OutputStream out = new FileOutputStream(tempFile)) {
      byte[] buffer = new byte[4096];
      int read;

      while ((read = in.read(buffer)) != -1) {
        out.write(buffer, 0, read);
      }
    }
    System.load(tempFile.getAbsolutePath());
  }

  /*
  If libmessaging_jni is embedded within this jar as a resource file, attempt
  to copy it to a temporary file and then load it. This allows the jar to be
  used even without a shared library existing on the filesystem.
  */
  private static void loadLibrary() {
    try {
      String libraryName = System.mapLibraryName("messaging_jni");
      try (InputStream in = Native.class.getResourceAsStream("/" + libraryName)) {
        if (in != null) {
          copyToTempFileAndLoad(in, libraryName);
        } else {
          System.loadLibrary("messaging_jni");
        }
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  static {
    loadLibrary();
    Logger_Initialize(MessagingProtocolLogger.INFO, Log.class);
  }

  private Native() {}

  /**
   * Keeps an object from being garbage-collected until this call completes.
   *
   * This can be used to keep a Java wrapper around a Rust object handle alive while
   * earlier calls use that Rust object handle. That is, you should call {@code keepAlive} 
   * <em>after</em> the code where an object must not be garbage-collected.
   * However, most of the time {@link NativeHandleGuard} is a better choice,
   * since the lifetime of the guard is clear.
   *
   * Effectively equivalent to Java 9's <a href="https://docs.oracle.com/javase/9/docs/api/java/lang/ref/Reference.html#reachabilityFence-java.lang.Object-"><code>reachabilityFence()</code></a>.
   * Uses {@code native} because the JVM can't look into the implementation of the method
   * and optimize away the use of {@code obj}. (The actual implementation does nothing.)
   */
  public static native void keepAlive(Object obj);

  public static native byte[] Aes256Cbc_Decrypt(byte[] ptext, byte[] key, byte[] iv);
  public static native byte[] Aes256Cbc_Encrypt(byte[] ptext, byte[] key, byte[] iv);

  public static native byte[] ECPrivateKey_Agree(long privateKey, long publicKey);
  public static native long ECPrivateKey_Deserialize(byte[] data);
  public static native void ECPrivateKey_Destroy(long handle);
  public static native long ECPrivateKey_Generate();
  public static native long ECPrivateKey_GetPublicKey(long k);
  public static native byte[] ECPrivateKey_Serialize(long obj);
  public static native byte[] ECPrivateKey_Sign(long key, byte[] message);

  public static native int ECPublicKey_Compare(long key1, long key2);
  public static native long ECPublicKey_Deserialize(byte[] data, int offset);
  public static native void ECPublicKey_Destroy(long handle);
  public static native boolean ECPublicKey_Equals(long lhs, long rhs);
  public static native byte[] ECPublicKey_GetPublicKeyBytes(long obj);
  public static native byte[] ECPublicKey_Serialize(long obj);
  public static native boolean ECPublicKey_Verify(long key, byte[] message, byte[] signature);

  public static native byte[] HKDF_DeriveSecrets(int outputLength, byte[] ikm, byte[] label, byte[] salt);

  public static native void Logger_Initialize(int maxLevel, Class loggerClass);
  public static native void Logger_SetMaxLevel(int maxLevel);

  public static native byte[] Mac_Compute(byte[] macKey, byte[] data);
  public static native boolean Mac_Verify(byte[] macKey, byte[] data, byte[] theirMac, int length);
}
