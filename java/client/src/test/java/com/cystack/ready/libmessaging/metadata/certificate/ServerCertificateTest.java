package com.cystack.ready.libmessaging.metadata.certificate;

import junit.framework.TestCase;

import com.cystack.ready.libmessaging.protocol.InvalidKeyException;
import com.cystack.ready.libmessaging.protocol.ecc.Curve;
import com.cystack.ready.libmessaging.protocol.ecc.ECKeyPair;

import com.cystack.ready.libmessaging.internal.Native;
import com.cystack.ready.libmessaging.internal.NativeHandleGuard;

public class ServerCertificateTest extends TestCase {

  public void testSignature() throws InvalidKeyException, InvalidCertificateException {
    ECKeyPair trustRoot = Curve.generateKeyPair();
    ECKeyPair keyPair   = Curve.generateKeyPair();

    try (
      NativeHandleGuard serverPublicGuard = new NativeHandleGuard(keyPair.getPublicKey());
      NativeHandleGuard trustRootPrivateGuard = new NativeHandleGuard(trustRoot.getPrivateKey());
    ) {
      ServerCertificate certificate = new ServerCertificate(
         Native.ServerCertificate_New(1, serverPublicGuard.nativeHandle(), trustRootPrivateGuard.nativeHandle()));
  
      new CertificateValidator(trustRoot.getPublicKey()).validate(certificate);
  
      byte[] serialized = certificate.getSerialized();
      new CertificateValidator(trustRoot.getPublicKey()).validate(new ServerCertificate(serialized));  
    }
  }

  public void testBadSignature() throws Exception {
    ECKeyPair trustRoot = Curve.generateKeyPair();
    ECKeyPair keyPair   = Curve.generateKeyPair();

    try (
      NativeHandleGuard serverPublicGuard = new NativeHandleGuard(keyPair.getPublicKey());
      NativeHandleGuard trustRootPrivateGuard = new NativeHandleGuard(trustRoot.getPrivateKey());
    ) {
      ServerCertificate certificate = new ServerCertificate(
         Native.ServerCertificate_New(1, serverPublicGuard.nativeHandle(), trustRootPrivateGuard.nativeHandle()));

      byte[] badSignature = certificate.getSerialized();

      badSignature[badSignature.length - 1] ^= 1;

      ServerCertificate badCert = new ServerCertificate(badSignature);

      try {
         new CertificateValidator(trustRoot.getPublicKey()).validate(new ServerCertificate(badSignature));
         fail();
      } catch (InvalidCertificateException e) {
         // good
      }
    }
  }

}
