package com.cystack.ready.libmessaging.metadata;

import junit.framework.TestCase;

import com.cystack.ready.libmessaging.metadata.SealedSessionCipher.DecryptionResult;
import com.cystack.ready.libmessaging.metadata.protocol.UnidentifiedSenderMessageContent;
import com.cystack.ready.libmessaging.metadata.certificate.CertificateValidator;
import com.cystack.ready.libmessaging.metadata.certificate.InvalidCertificateException;
import com.cystack.ready.libmessaging.metadata.certificate.SenderCertificate;
import com.cystack.ready.libmessaging.metadata.certificate.ServerCertificate;
import com.cystack.ready.libmessaging.protocol.IdentityKeyPair;
import com.cystack.ready.libmessaging.protocol.InvalidKeyException;
import com.cystack.ready.libmessaging.protocol.InvalidMessageException;
import com.cystack.ready.libmessaging.protocol.InvalidRegistrationIdException;
import com.cystack.ready.libmessaging.protocol.InvalidVersionException;
import com.cystack.ready.libmessaging.protocol.LegacyMessageException;
import com.cystack.ready.libmessaging.protocol.NoSessionException;
import com.cystack.ready.libmessaging.protocol.SessionBuilder;
import com.cystack.ready.libmessaging.protocol.SessionCipher;
import com.cystack.ready.libmessaging.protocol.SignalProtocolAddress;
import com.cystack.ready.libmessaging.protocol.UntrustedIdentityException;
import com.cystack.ready.libmessaging.protocol.ecc.Curve;
import com.cystack.ready.libmessaging.protocol.ecc.ECKeyPair;
import com.cystack.ready.libmessaging.protocol.ecc.ECPublicKey;
import com.cystack.ready.libmessaging.protocol.groups.GroupCipher;
import com.cystack.ready.libmessaging.protocol.groups.GroupSessionBuilder;
import com.cystack.ready.libmessaging.protocol.kem.KEMKeyPair;
import com.cystack.ready.libmessaging.protocol.kem.KEMKeyType;
import com.cystack.ready.libmessaging.protocol.message.CiphertextMessage;
import com.cystack.ready.libmessaging.protocol.message.DecryptionErrorMessage;
import com.cystack.ready.libmessaging.protocol.message.PlaintextContent;
import com.cystack.ready.libmessaging.protocol.message.SenderKeyDistributionMessage;
import com.cystack.ready.libmessaging.protocol.state.PreKeyBundle;
import com.cystack.ready.libmessaging.protocol.state.PreKeyRecord;
import com.cystack.ready.libmessaging.protocol.state.SessionRecord;
import com.cystack.ready.libmessaging.protocol.state.SignedPreKeyRecord;
import com.cystack.ready.libmessaging.protocol.state.KyberPreKeyRecord;

import com.cystack.ready.libmessaging.internal.Native;
import com.cystack.ready.libmessaging.internal.NativeHandleGuard;

import com.cystack.ready.libmessaging.protocol.util.Hex;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

public class SealedSessionCipherTest extends TestCase {

  private static SignedPreKeyRecord generateSignedPreKey(IdentityKeyPair identityKeyPair, int signedPreKeyId)
      throws InvalidKeyException
  {
    ECKeyPair keyPair   = Curve.generateKeyPair();
    byte[]    signature = Curve.calculateSignature(identityKeyPair.getPrivateKey(), keyPair.getPublicKey().serialize());

    return new SignedPreKeyRecord(signedPreKeyId, System.currentTimeMillis(), keyPair, signature);
  }

  private static KyberPreKeyRecord generateKyberPreKey(IdentityKeyPair identityKeyPair, int kyberPreKeyId)
      throws InvalidKeyException {
    KEMKeyPair keyPair   = KEMKeyPair.generate(KEMKeyType.KYBER_1024);
    byte[]     signature = Curve.calculateSignature(identityKeyPair.getPrivateKey(), keyPair.getPublicKey().serialize());

    return new KyberPreKeyRecord(kyberPreKeyId, System.currentTimeMillis(), keyPair, signature);
  }

  public void testEncryptDecrypt() throws UntrustedIdentityException, InvalidKeyException, InvalidCertificateException, InvalidMetadataMessageException, ProtocolDuplicateMessageException, ProtocolUntrustedIdentityException, ProtocolLegacyMessageException, ProtocolInvalidKeyException, InvalidMetadataVersionException, ProtocolInvalidVersionException, ProtocolInvalidMessageException, ProtocolInvalidKeyIdException, ProtocolNoSessionException, SelfSendException {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
    SignalProtocolAddress bobAddress           = new SignalProtocolAddress("+14152222222", 1);

    initializeSessions(aliceStore, bobStore, bobAddress);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1, aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    byte[] ciphertext = aliceCipher.encrypt(bobAddress, senderCertificate, "smert za smert".getBytes());


    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, UUID.fromString("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"), "+14152222222", 1);

    DecryptionResult plaintext = bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31335);

    assertEquals(new String(plaintext.getPaddedMessage()), "smert za smert");
    assertEquals(plaintext.getSenderUuid(), "9d0652a3-dcc3-4d11-975f-74d61598733f");
    assertEquals(plaintext.getSenderE164().get(), "+14151111111");
    assertEquals(plaintext.getDeviceId(), 1);
  }

  public void testEncryptDecryptUntrusted() throws Exception {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
    SignalProtocolAddress bobAddress           = new SignalProtocolAddress("+14152222222", 1);

    initializeSessions(aliceStore, bobStore, bobAddress);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    ECKeyPair           falseTrustRoot    = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(falseTrustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1, aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    byte[] ciphertext = aliceCipher.encrypt(bobAddress, senderCertificate, "\u0438 \u0432\u043E\u0442 \u044F".getBytes());

    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, UUID.fromString("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"), "+14152222222", 1);

    try {
      bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31335);
      throw new AssertionError();
    } catch (InvalidMetadataMessageException e) {
      // good
    }
  }

  public void testEncryptDecryptExpired() throws Exception {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
    SignalProtocolAddress bobAddress           = new SignalProtocolAddress("+14152222222", 1);

    initializeSessions(aliceStore, bobStore, bobAddress);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1, aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    byte[] ciphertext = aliceCipher.encrypt(bobAddress, senderCertificate, "\u0438 \u0432\u043E\u0442 \u044F".getBytes());

    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, UUID.fromString("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"), "+14152222222", 1);

    try {
      bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31338);
      throw new AssertionError();
    } catch (InvalidMetadataMessageException e) {
      // good
    }
  }

  public void testEncryptFromWrongIdentity() throws Exception {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
    SignalProtocolAddress bobAddress           = new SignalProtocolAddress("+14152222222", 1);

    initializeSessions(aliceStore, bobStore, bobAddress);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    ECKeyPair           randomKeyPair     = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1, randomKeyPair.getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    byte[] ciphertext = aliceCipher.encrypt(bobAddress, senderCertificate, "smert za smert".getBytes());


    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, UUID.fromString("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"), "+14152222222", 1);

    try {
      bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), ciphertext, 31335);
    } catch (InvalidMetadataMessageException e) {
      // good
    }
  }

  public void testEncryptDecryptGroup() throws UntrustedIdentityException, InvalidKeyException, InvalidCertificateException, InvalidMessageException, InvalidVersionException, InvalidMetadataMessageException, InvalidRegistrationIdException, LegacyMessageException, NoSessionException, ProtocolDuplicateMessageException, ProtocolUntrustedIdentityException, ProtocolLegacyMessageException, ProtocolInvalidKeyException, InvalidMetadataVersionException, ProtocolInvalidVersionException, ProtocolInvalidMessageException, ProtocolInvalidKeyIdException, ProtocolNoSessionException, SelfSendException {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
    SignalProtocolAddress bobAddress           = new SignalProtocolAddress("e80f7bbe-5b94-471e-bd8c-2173654ea3d1", 1);

    initializeSessions(aliceStore, bobStore, bobAddress);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1, aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    SignalProtocolAddress senderAddress = new SignalProtocolAddress("9d0652a3-dcc3-4d11-975f-74d61598733f", 1);
    UUID distributionId = UUID.fromString("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6");

    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, UUID.fromString("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"), "+14152222222", 1);

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, senderAddress);
    GroupCipher bobGroupCipher   = new GroupCipher(bobStore, senderAddress);

    SenderKeyDistributionMessage sentAliceDistributionMessage     = aliceSessionBuilder.create(senderAddress, distributionId);
    SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());
    bobSessionBuilder.process(senderAddress, receivedAliceDistributionMessage);

    CiphertextMessage ciphertextFromAlice = aliceGroupCipher.encrypt(distributionId, "smert ze smert".getBytes());

    UnidentifiedSenderMessageContent usmcFromAlice = new UnidentifiedSenderMessageContent(ciphertextFromAlice, senderCertificate, UnidentifiedSenderMessageContent.CONTENT_HINT_IMPLICIT, Optional.of(new byte[]{42, 43}));

    byte[] aliceMessage = aliceCipher.multiRecipientEncrypt(Arrays.asList(bobAddress), usmcFromAlice);
    byte[] bobMessage = SealedSessionCipher.multiRecipientMessageForSingleRecipient(aliceMessage);

    DecryptionResult plaintext = bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), bobMessage, 31335);

    assertEquals(new String(plaintext.getPaddedMessage()), "smert ze smert");
    assertEquals(plaintext.getSenderUuid(), "9d0652a3-dcc3-4d11-975f-74d61598733f");
    assertEquals(plaintext.getSenderE164().get(), "+14151111111");
    assertEquals(plaintext.getDeviceId(), 1);
    assertTrue(Arrays.equals(plaintext.getGroupId().get(), new byte[]{42, 43}));
  }


  public void testEncryptGroupWithBadRegistrationId() throws UntrustedIdentityException, InvalidKeyException, InvalidCertificateException, InvalidMessageException, InvalidMetadataMessageException, InvalidRegistrationIdException, LegacyMessageException, NoSessionException, ProtocolDuplicateMessageException, ProtocolUntrustedIdentityException, ProtocolLegacyMessageException, ProtocolInvalidKeyException, InvalidMetadataVersionException, ProtocolInvalidVersionException, ProtocolInvalidMessageException, ProtocolInvalidKeyIdException, ProtocolNoSessionException, SelfSendException {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
    SignalProtocolAddress bobAddress           = new SignalProtocolAddress("e80f7bbe-5b94-471e-bd8c-2173654ea3d1", 1);

    ECKeyPair          bobPreKey       = Curve.generateKeyPair();
    IdentityKeyPair    bobIdentityKey  = bobStore.getIdentityKeyPair();
    SignedPreKeyRecord bobSignedPreKey = generateSignedPreKey(bobIdentityKey, 2);
    KyberPreKeyRecord bobKyberPreKey = generateKyberPreKey(bobIdentityKey, 12);

    PreKeyBundle bobBundle = new PreKeyBundle(0x4000, 1, 1, bobPreKey.getPublicKey(), 2, bobSignedPreKey.getKeyPair().getPublicKey(), bobSignedPreKey.getSignature(), bobIdentityKey.getPublicKey(), 12, bobKyberPreKey.getKeyPair().getPublicKey(), bobKyberPreKey.getSignature());
    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, bobAddress);
    aliceSessionBuilder.process(bobBundle);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1, aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    SignalProtocolAddress senderAddress = new SignalProtocolAddress("9d0652a3-dcc3-4d11-975f-74d61598733f", 1);
    UUID distributionId = UUID.fromString("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6");

    GroupSessionBuilder aliceGroupSessionBuilder = new GroupSessionBuilder(aliceStore);
    SenderKeyDistributionMessage sentAliceDistributionMessage = aliceGroupSessionBuilder.create(senderAddress, distributionId);

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, senderAddress);
    CiphertextMessage ciphertextFromAlice = aliceGroupCipher.encrypt(distributionId, "smert ze smert".getBytes());

    UnidentifiedSenderMessageContent usmcFromAlice = new UnidentifiedSenderMessageContent(ciphertextFromAlice, senderCertificate, UnidentifiedSenderMessageContent.CONTENT_HINT_IMPLICIT, Optional.of(new byte[]{42, 43}));

    try {
      byte[] aliceMessage = aliceCipher.multiRecipientEncrypt(Arrays.asList(bobAddress), usmcFromAlice);
      fail("should have thrown");
    } catch (InvalidRegistrationIdException e) {
      assertEquals(e.getAddress(), bobAddress);
    }
  }

  public void testEncryptGroupWithManyRecipients() throws UntrustedIdentityException, InvalidKeyException, InvalidCertificateException, InvalidMessageException, InvalidMetadataMessageException, InvalidRegistrationIdException, LegacyMessageException, NoSessionException, ProtocolDuplicateMessageException, ProtocolUntrustedIdentityException, ProtocolLegacyMessageException, ProtocolInvalidKeyException, InvalidMetadataVersionException, ProtocolInvalidVersionException, ProtocolInvalidMessageException, ProtocolInvalidKeyIdException, ProtocolNoSessionException, SelfSendException {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore carolStore = new TestInMemorySignalProtocolStore();
    SignalProtocolAddress bobAddress           = new SignalProtocolAddress("e80f7bbe-5b94-471e-bd8c-2173654ea3d1", 1);
    SignalProtocolAddress carolAddress         = new SignalProtocolAddress("38381c3b-2606-4ca7-9310-7cb927f2ab4a", 1);

    ECKeyPair          bobPreKey       = Curve.generateKeyPair();
    IdentityKeyPair    bobIdentityKey  = bobStore.getIdentityKeyPair();
    SignedPreKeyRecord bobSignedPreKey = generateSignedPreKey(bobIdentityKey, 2);
    KyberPreKeyRecord  bobKyberPreKey  = generateKyberPreKey(bobIdentityKey, 12);

    PreKeyBundle bobBundle = new PreKeyBundle(0x1234, 1, 1, bobPreKey.getPublicKey(), 2, bobSignedPreKey.getKeyPair().getPublicKey(), bobSignedPreKey.getSignature(), bobIdentityKey.getPublicKey(), 12, bobKyberPreKey.getKeyPair().getPublicKey(), bobKyberPreKey.getSignature());
    SessionBuilder aliceSessionBuilderForBob = new SessionBuilder(aliceStore, bobAddress);
    aliceSessionBuilderForBob.process(bobBundle);

    ECKeyPair          carolPreKey       = Curve.generateKeyPair();
    IdentityKeyPair    carolIdentityKey  = carolStore.getIdentityKeyPair();
    SignedPreKeyRecord carolSignedPreKey = generateSignedPreKey(carolIdentityKey, 2);
    KyberPreKeyRecord  carolKyberPreKey  = generateKyberPreKey(carolIdentityKey, 12);

    PreKeyBundle carolBundle = new PreKeyBundle(0x1111, 1, 1, carolPreKey.getPublicKey(), 2, carolSignedPreKey.getKeyPair().getPublicKey(), carolSignedPreKey.getSignature(), carolIdentityKey.getPublicKey(), 12, carolKyberPreKey.getKeyPair().getPublicKey(), carolKyberPreKey.getSignature());
    SessionBuilder aliceSessionBuilderForCarol = new SessionBuilder(aliceStore, carolAddress);
    aliceSessionBuilderForCarol.process(carolBundle);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1, aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    SignalProtocolAddress senderAddress = new SignalProtocolAddress("9d0652a3-dcc3-4d11-975f-74d61598733f", 1);
    UUID distributionId = UUID.fromString("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6");

    GroupSessionBuilder aliceGroupSessionBuilder = new GroupSessionBuilder(aliceStore);
    SenderKeyDistributionMessage sentAliceDistributionMessage = aliceGroupSessionBuilder.create(senderAddress, distributionId);

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, senderAddress);
    CiphertextMessage ciphertextFromAlice = aliceGroupCipher.encrypt(distributionId, "smert ze smert".getBytes());

    UnidentifiedSenderMessageContent usmcFromAlice = new UnidentifiedSenderMessageContent(ciphertextFromAlice, senderCertificate, UnidentifiedSenderMessageContent.CONTENT_HINT_IMPLICIT, Optional.of(new byte[]{42, 43}));

    ArrayList<SignalProtocolAddress> addresses = new ArrayList<>();
    for (int i = 0; i < 1000; ++i) {
      // Alternate between the two to avoid peephole optimizations.
      addresses.add(bobAddress);
      addresses.add(carolAddress);
    }

    // Just check that we don't throw an error or crash.
    byte[] aliceMessage = aliceCipher.multiRecipientEncrypt(addresses, usmcFromAlice);
  }

  public void testEncryptGroupWithMissingSession() throws UntrustedIdentityException, InvalidKeyException, InvalidCertificateException, InvalidMessageException, InvalidMetadataMessageException, InvalidRegistrationIdException, LegacyMessageException, NoSessionException, ProtocolDuplicateMessageException, ProtocolUntrustedIdentityException, ProtocolLegacyMessageException, ProtocolInvalidKeyException, InvalidMetadataVersionException, ProtocolInvalidVersionException, ProtocolInvalidMessageException, ProtocolInvalidKeyIdException, ProtocolNoSessionException, SelfSendException {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
    SignalProtocolAddress bobAddress           = new SignalProtocolAddress("e80f7bbe-5b94-471e-bd8c-2173654ea3d1", 1);
    SignalProtocolAddress carolAddress         = new SignalProtocolAddress("38381c3b-2606-4ca7-9310-7cb927f2ab4a", 1);

    ECKeyPair          bobPreKey       = Curve.generateKeyPair();
    IdentityKeyPair    bobIdentityKey  = bobStore.getIdentityKeyPair();
    SignedPreKeyRecord bobSignedPreKey = generateSignedPreKey(bobIdentityKey, 2);
    KyberPreKeyRecord  bobKyberPreKey  = generateKyberPreKey(bobIdentityKey, 12);

    PreKeyBundle bobBundle = new PreKeyBundle(0x1234, 1, 1, bobPreKey.getPublicKey(), 2, bobSignedPreKey.getKeyPair().getPublicKey(), bobSignedPreKey.getSignature(), bobIdentityKey.getPublicKey(), 12, bobKyberPreKey.getKeyPair().getPublicKey(), bobKyberPreKey.getSignature());
    SessionBuilder aliceSessionBuilderForBob = new SessionBuilder(aliceStore, bobAddress);
    aliceSessionBuilderForBob.process(bobBundle);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1, aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    SignalProtocolAddress senderAddress = new SignalProtocolAddress("9d0652a3-dcc3-4d11-975f-74d61598733f", 1);
    UUID distributionId = UUID.fromString("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6");

    GroupSessionBuilder aliceGroupSessionBuilder = new GroupSessionBuilder(aliceStore);
    SenderKeyDistributionMessage sentAliceDistributionMessage = aliceGroupSessionBuilder.create(senderAddress, distributionId);

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, senderAddress);
    CiphertextMessage ciphertextFromAlice = aliceGroupCipher.encrypt(distributionId, "smert ze smert".getBytes());

    UnidentifiedSenderMessageContent usmcFromAlice = new UnidentifiedSenderMessageContent(ciphertextFromAlice, senderCertificate, UnidentifiedSenderMessageContent.CONTENT_HINT_IMPLICIT, Optional.of(new byte[]{42, 43}));

    ArrayList<SignalProtocolAddress> addresses = new ArrayList<>();
    for (int i = 0; i < 1000; ++i) {
      // Alternate between the two to avoid peephole optimizations.
      addresses.add(bobAddress);
      addresses.add(carolAddress);
    }

    // Just check that we don't throw an error or crash.
    try {
      aliceCipher.multiRecipientEncrypt(addresses, usmcFromAlice);
    } catch (NoSessionException e) {
      assertEquals(e.getAddress(), carolAddress);
    }
  }

  public void testProtocolException() throws UntrustedIdentityException, InvalidKeyException, InvalidCertificateException, InvalidMessageException, InvalidMetadataMessageException, InvalidRegistrationIdException, LegacyMessageException, NoSessionException, ProtocolDuplicateMessageException, ProtocolUntrustedIdentityException, ProtocolLegacyMessageException, ProtocolInvalidKeyException, InvalidMetadataVersionException, ProtocolInvalidVersionException, ProtocolInvalidMessageException, ProtocolInvalidKeyIdException, ProtocolNoSessionException, SelfSendException {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
    SignalProtocolAddress bobAddress           = new SignalProtocolAddress("e80f7bbe-5b94-471e-bd8c-2173654ea3d1", 1);

    initializeSessions(aliceStore, bobStore, bobAddress);

    ECKeyPair           trustRoot         = Curve.generateKeyPair();
    SenderCertificate   senderCertificate = createCertificateFor(trustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1, aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
    SealedSessionCipher aliceCipher       = new SealedSessionCipher(aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    SignalProtocolAddress senderAddress = new SignalProtocolAddress("9d0652a3-dcc3-4d11-975f-74d61598733f", 1);
    UUID distributionId = UUID.fromString("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6");

    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, UUID.fromString("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"), "+14152222222", 1);

    GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
    GroupSessionBuilder bobSessionBuilder   = new GroupSessionBuilder(bobStore);

    GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, senderAddress);
    GroupCipher bobGroupCipher   = new GroupCipher(bobStore, senderAddress);

    // Send a group message without sending the distribution ID first.
    aliceSessionBuilder.create(senderAddress, distributionId);
    CiphertextMessage ciphertextFromAlice = aliceGroupCipher.encrypt(distributionId, "smert ze smert".getBytes());

    UnidentifiedSenderMessageContent usmcFromAlice = new UnidentifiedSenderMessageContent(ciphertextFromAlice, senderCertificate, UnidentifiedSenderMessageContent.CONTENT_HINT_RESENDABLE, Optional.of(new byte[]{42, 1}));

    byte[] aliceMessage = aliceCipher.multiRecipientEncrypt(Arrays.asList(bobAddress), usmcFromAlice);
    byte[] bobMessage = SealedSessionCipher.multiRecipientMessageForSingleRecipient(aliceMessage);

    try {
      bobCipher.decrypt(new CertificateValidator(trustRoot.getPublicKey()), bobMessage, 31335);
      fail("should have thrown");
    } catch (ProtocolNoSessionException e) {
      assertEquals(e.getSender(), "9d0652a3-dcc3-4d11-975f-74d61598733f");
      assertEquals(e.getSenderDevice(), 1);
      assertEquals(e.getContentHint(), UnidentifiedSenderMessageContent.CONTENT_HINT_RESENDABLE);
      assertEquals(Hex.toStringCondensed(e.getGroupId().get()), Hex.toStringCondensed(new byte[]{42, 1}));
    }
  }

  public void testDecryptionErrorMessage() throws InvalidCertificateException, InvalidKeyException, InvalidMessageException, InvalidMetadataMessageException, InvalidMetadataVersionException, ProtocolDuplicateMessageException, ProtocolInvalidKeyException, ProtocolInvalidKeyIdException, ProtocolInvalidMessageException, ProtocolInvalidVersionException, ProtocolLegacyMessageException, ProtocolNoSessionException, ProtocolUntrustedIdentityException, SelfSendException, UntrustedIdentityException {
    TestInMemorySignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    TestInMemorySignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();
    SignalProtocolAddress bobAddress           = new SignalProtocolAddress("+14152222222", 1);

    initializeSessions(aliceStore, bobStore, bobAddress);

    ECKeyPair            trustRoot            = Curve.generateKeyPair();
    CertificateValidator certificateValidator = new CertificateValidator(trustRoot.getPublicKey());
    SenderCertificate    senderCertificate    = createCertificateFor(trustRoot, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1, aliceStore.getIdentityKeyPair().getPublicKey().getPublicKey(), 31337);
    SealedSessionCipher  aliceCipher          = new SealedSessionCipher(aliceStore, UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f"), "+14151111111", 1);

    // Send a message from Alice to Bob to set up the session.
    byte[] ciphertext = aliceCipher.encrypt(bobAddress, senderCertificate, "smert za smert".getBytes());

    SealedSessionCipher bobCipher = new SealedSessionCipher(bobStore, UUID.fromString("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"), "+14152222222", 1);

    bobCipher.decrypt(certificateValidator, ciphertext, 31335);

    // Pretend Bob's reply fails to decrypt.
    SignalProtocolAddress aliceAddress = new SignalProtocolAddress("9d0652a3-dcc3-4d11-975f-74d61598733f", 1);
    SessionCipher bobUnsealedCipher = new SessionCipher(bobStore, aliceAddress);
    CiphertextMessage bobMessage = bobUnsealedCipher.encrypt("reply".getBytes());

    DecryptionErrorMessage errorMessage = DecryptionErrorMessage.forOriginalMessage(bobMessage.serialize(), bobMessage.getType(), 408, bobAddress.getDeviceId());
    PlaintextContent errorMessageContent = new PlaintextContent(errorMessage);
    UnidentifiedSenderMessageContent errorMessageUsmc = new UnidentifiedSenderMessageContent(errorMessageContent, senderCertificate, UnidentifiedSenderMessageContent.CONTENT_HINT_IMPLICIT, Optional.<byte[]>empty());
    byte[] errorMessageCiphertext = aliceCipher.encrypt(bobAddress, errorMessageUsmc);

    DecryptionResult result = bobCipher.decrypt(certificateValidator, errorMessageCiphertext, 31335);
    DecryptionErrorMessage bobErrorMessage = DecryptionErrorMessage.extractFromSerializedContent(result.getPaddedMessage());
    assertEquals(bobErrorMessage.getTimestamp(), 408);
    assertEquals(bobErrorMessage.getDeviceId(), bobAddress.getDeviceId());

    SessionRecord bobSessionWithAlice = bobStore.loadSession(aliceAddress);
    assert(bobSessionWithAlice.currentRatchetKeyMatches(bobErrorMessage.getRatchetKey().get()));
  }

  private SenderCertificate createCertificateFor(ECKeyPair trustRoot, UUID uuid, String e164, int deviceId, ECPublicKey identityKey, long expires)
      throws InvalidKeyException, InvalidCertificateException {
    ECKeyPair serverKey = Curve.generateKeyPair();

    try (
      NativeHandleGuard serverPublicGuard = new NativeHandleGuard(serverKey.getPublicKey());
      NativeHandleGuard trustRootPrivateGuard = new NativeHandleGuard(trustRoot.getPrivateKey());
    ) {
      ServerCertificate serverCertificate = new ServerCertificate(Native.ServerCertificate_New(1, serverPublicGuard.nativeHandle(), trustRootPrivateGuard.nativeHandle()));

      try (
        NativeHandleGuard identityGuard = new NativeHandleGuard(identityKey);
        NativeHandleGuard serverCertificateGuard = new NativeHandleGuard(serverCertificate);
        NativeHandleGuard serverPrivateGuard = new NativeHandleGuard(serverKey.getPrivateKey());
      ) {
        return new SenderCertificate(Native.SenderCertificate_New(uuid.toString(), e164, deviceId, identityGuard.nativeHandle(), expires, serverCertificateGuard.nativeHandle(), serverPrivateGuard.nativeHandle()));
      }
    }
  }

  private void initializeSessions(TestInMemorySignalProtocolStore aliceStore, TestInMemorySignalProtocolStore bobStore, SignalProtocolAddress bobAddress)
      throws InvalidKeyException, UntrustedIdentityException
  {
    ECKeyPair          bobPreKey       = Curve.generateKeyPair();
    IdentityKeyPair    bobIdentityKey  = bobStore.getIdentityKeyPair();
    SignedPreKeyRecord bobSignedPreKey = generateSignedPreKey(bobIdentityKey, 2);
    KyberPreKeyRecord  bobKyberPreKey  = generateKyberPreKey(bobIdentityKey, 12);

    PreKeyBundle bobBundle             = new PreKeyBundle(1, 1, 1, bobPreKey.getPublicKey(), 2, bobSignedPreKey.getKeyPair().getPublicKey(), bobSignedPreKey.getSignature(), bobIdentityKey.getPublicKey(), 12, bobKyberPreKey.getKeyPair().getPublicKey(), bobKyberPreKey.getSignature());
    SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, bobAddress);
    aliceSessionBuilder.process(bobBundle);

    bobStore.storeSignedPreKey(2, bobSignedPreKey);
    bobStore.storeKyberPreKey(12, bobKyberPreKey);
    bobStore.storePreKey(1, new PreKeyRecord(1, bobPreKey));
  }
}
