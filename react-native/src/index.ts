//
// Copyright 2023 Ready.io
//

/* eslint-disable no-bitwise */
/* eslint-disable camelcase */
/* eslint-disable lines-between-class-members */
/* eslint-disable no-empty-function */
/* eslint-disable @typescript-eslint/no-unused-vars */

import { randomBytes } from 'react-native-randombytes'
import {
  PreKeyWhisperMessage,
  WhisperMessage,
} from '@privacyresearch/libsignal-protocol-protobuf-ts'
import { generateKeyPair, sign } from 'curve25519-js'

import { ProtocolAddress } from './Address'
// import * as Errors from './Errors'
// import * as Native from './Native'
import { SessionBuilder } from './session-builder'
import { type MessageType, SessionCipher } from './session-cipher'
import { SessionRecord } from './session-record'
import { type KeyPairType } from './types'

export * from './Errors'
export * from './Address'
export * from './types'

// Native.registerErrors(Errors)

// These enums must be kept in sync with their Rust counterparts.

export enum CiphertextMessageType {
  Whisper = 1,
  PreKey = 3,
  SenderKey = 7,
  Plaintext = 8,
}

export enum Direction {
  Sending,
  Receiving,
}

export class PublicKey {
  // readonly _nativeHandle: Native.PublicKey

  constructor(readonly value: Uint8Array) {}

  // private constructor(handle: Native.PublicKey) {
  //   this._nativeHandle = handle
  // }

  // static _fromNativeHandle(handle: Native.PublicKey): PublicKey {
  //   return new PublicKey(handle)
  // }

  static deserialize(buf: Uint8Array): PublicKey {
    // return new PublicKey(Native.PublicKey_Deserialize(buf))
    return new PublicKey(buf)
  }

  /// Returns -1, 0, or 1
  compare(other: PublicKey): number {
    throw new Error('Pubkey')
    // return Native.PublicKey_Compare(this, other)
  }

  serialize(): Uint8Array {
    return this.value
    // return Native.PublicKey_Serialize(this)
  }

  getPublicKeyBytes(): Uint8Array {
    throw new Error('Pubkey')
    // return Native.PublicKey_GetPublicKeyBytes(this)
  }

  verify(msg: Uint8Array, sig: Uint8Array): boolean {
    throw new Error('Pubkey')
    // return Native.PublicKey_Verify(this, msg, sig)
  }

  verifyAlternateIdentity(other: PublicKey, signature: Uint8Array): boolean {
    throw new Error('Pubkey')
    // return Native.IdentityKey_VerifyAlternateIdentity(this, other, signature)
  }
}

export class PrivateKey {
  // readonly _nativeHandle: Native.PrivateKey

  private constructor(readonly value: Uint8Array, private readonly publicKey: Uint8Array) {}
  // private constructor(handle: Native.PrivateKey) {
  //   this._nativeHandle = handle
  // }

  // static _fromNativeHandle(handle: Native.PrivateKey): PrivateKey {
  //   return new PrivateKey(handle)
  // }

  static generate(): PrivateKey {
    const raw_keys = generateKeyPair(randomBytes(32))
    return new PrivateKey(raw_keys.private, raw_keys.public) // Native.PrivateKey_Generate())
  }

  static deserialize(buf: Uint8Array): PrivateKey {
    const raw_keys = generateKeyPair(buf)
    return new PrivateKey(raw_keys.private, raw_keys.public) // Native.PrivateKey_Deserialize(buf))
  }

  serialize(): Uint8Array {
    return this.value
    // return Native.PrivateKey_Serialize(this)
  }

  sign(msg: Uint8Array): Uint8Array {
    return sign(this.value, msg, new Uint8Array(randomBytes(64)))
    // return Native.PrivateKey_Sign(this, msg)
  }

  agree(other_key: PublicKey): Uint8Array {
    throw new Error('////')
    // return Native.PrivateKey_Agree(this, other_key)
  }

  getPublicKey(): PublicKey {
    return new PublicKey(this.publicKey)
    // return PublicKey._fromNativeHandle(Native.PrivateKey_GetPublicKey(this))
  }
}

export class IdentityKeyPair {
  readonly publicKey: PublicKey
  readonly privateKey: PrivateKey

  constructor(publicKey: PublicKey, privateKey: PrivateKey) {
    this.publicKey = publicKey
    this.privateKey = privateKey
  }

  static generate(): IdentityKeyPair {
    const privateKey = PrivateKey.generate()
    return new IdentityKeyPair(privateKey.getPublicKey(), privateKey)
  }

  static deserialize(buffer: Uint8Array): IdentityKeyPair {
    throw new Error('.....deserialize.')
    // const { privateKey, publicKey } = Native.IdentityKeyPair_Deserialize(buffer)
    // return new IdentityKeyPair(
    //   PublicKey._fromNativeHandle(publicKey),
    //   PrivateKey._fromNativeHandle(privateKey)
    // )
  }

  serialize(): Uint8Array {
    throw new Error('.....serialize.')
    // return Native.IdentityKeyPair_Serialize(this.publicKey, this.privateKey)
  }

  signAlternateIdentity(other: PublicKey): Uint8Array {
    throw new Error('......signAlternateIdentity')
    // return Native.IdentityKeyPair_SignAlternateIdentity(this.publicKey, this.privateKey, other)
  }
}

export class PreKeyBundle {
  // readonly _nativeHandle: Native.PreKeyBundle

  // private constructor(handle: Native.PreKeyBundle) {
  //   this._nativeHandle = handle
  // }

  private constructor(
    private registration_id: number,
    private device_id: number,
    private prekey_id: number | null,
    private prekey: PublicKey | null,
    private signed_prekey_id: number,
    private signed_prekey: PublicKey,
    private signed_prekey_signature: Uint8Array,
    private identity_key: PublicKey
  ) {}

  static new(
    registration_id: number,
    device_id: number,
    prekey_id: number | null,
    prekey: PublicKey | null,
    signed_prekey_id: number,
    signed_prekey: PublicKey,
    signed_prekey_signature: Uint8Array,
    identity_key: PublicKey
  ): PreKeyBundle {
    return new PreKeyBundle(
      // Native.PreKeyBundle_New(
      registration_id,
      device_id,
      prekey_id,
      prekey != null ? prekey : null,
      // prekey?,
      signed_prekey_id,
      signed_prekey,
      signed_prekey_signature,
      identity_key
      // )
    )
  }

  deviceId(): number {
    // return Native.PreKeyBundle_GetDeviceId(this)
    return this.device_id
  }

  identityKey(): PublicKey {
    // return PublicKey._fromNativeHandle(Native.PreKeyBundle_GetIdentityKey(this))
    return this.identity_key
  }

  preKeyId(): number | null {
    // return Native.PreKeyBundle_GetPreKeyId(this)
    return this.prekey_id
  }

  preKeyPublic(): PublicKey | null {
    // const handle = Native.PreKeyBundle_GetPreKeyPublic(this)

    // if (handle == null) {
    //   return null
    // }
    // return PublicKey._fromNativeHandle(handle)
    return this.prekey
  }

  registrationId(): number {
    // return Native.PreKeyBundle_GetRegistrationId(this)
    return this.registration_id
  }

  signedPreKeyId(): number {
    // return Native.PreKeyBundle_GetSignedPreKeyId(this)
    return this.signed_prekey_id
  }

  signedPreKeyPublic(): PublicKey {
    // return PublicKey._fromNativeHandle(Native.PreKeyBundle_GetSignedPreKeyPublic(this))
    return this.signed_prekey
  }

  signedPreKeySignature(): Uint8Array {
    // return Native.PreKeyBundle_GetSignedPreKeySignature(this)
    return this.signed_prekey_signature
  }
}

export class PreKeyRecord {
  // readonly _nativeHandle: Native.PreKeyRecord

  // private constructor(handle: Native.PreKeyRecord) {
  //   this._nativeHandle = handle
  // }

  private constructor(
    readonly _id: number,
    readonly _pubKey: PublicKey,
    readonly _privKey: PrivateKey
  ) {}

  // static _fromNativeHandle(nativeHandle: Native.PreKeyRecord): PreKeyRecord {
  //   return new PreKeyRecord(nativeHandle)
  // }

  static new(id: number, pubKey: PublicKey, privKey: PrivateKey): PreKeyRecord {
    // return new PreKeyRecord(Native.PreKeyRecord_New(id, pubKey, privKey))
    return new PreKeyRecord(id, pubKey, privKey)
  }

  static deserialize(buffer: Uint8Array): PreKeyRecord {
    throw new Error('......PreKeyRecord,deserialize')
    // return new PreKeyRecord(Native.PreKeyRecord_Deserialize(buffer))
  }

  id(): number {
    // return Native.PreKeyRecord_GetId(this)
    return this._id
  }

  privateKey(): PrivateKey {
    // return PrivateKey._fromNativeHandle(Native.PreKeyRecord_GetPrivateKey(this))
    return this._privKey
  }

  publicKey(): PublicKey {
    // return PublicKey._fromNativeHandle(Native.PreKeyRecord_GetPublicKey(this))
    return this._pubKey
  }

  serialize(): Uint8Array {
    throw new Error('......PreKeyRecord')
    // return Native.PreKeyRecord_Serialize(this)
  }
}

export class SignedPreKeyRecord {
  // readonly _nativeHandle: Native.SignedPreKeyRecord

  // private constructor(handle: Native.SignedPreKeyRecord) {
  //   this._nativeHandle = handle
  // }

  private constructor(
    private _id: number,
    private _timestamp: number,
    private _pubKey: PublicKey,
    private _privKey: PrivateKey,
    private _signature: Uint8Array
  ) {}

  // static _fromNativeHandle(nativeHandle: Native.SignedPreKeyRecord): SignedPreKeyRecord {
  //   return new SignedPreKeyRecord(nativeHandle)
  // }

  static new(
    id: number,
    timestamp: number,
    pubKey: PublicKey,
    privKey: PrivateKey,
    signature: Uint8Array
  ): SignedPreKeyRecord {
    // return new SignedPreKeyRecord(
    //   Native.SignedPreKeyRecord_New(id, timestamp, pubKey, privKey, signature)
    // )
    return new SignedPreKeyRecord(id, timestamp, pubKey, privKey, signature)
  }

  static deserialize(buffer: Uint8Array): SignedPreKeyRecord {
    throw new Error('......SignedPreKeyRecord')
    // return new SignedPreKeyRecord(Native.SignedPreKeyRecord_Deserialize(buffer))
  }

  serialize(): Uint8Array {
    throw new Error('......SignedPreKeyRecord')
    // return Native.SignedPreKeyRecord_Serialize(this)
  }

  id(): number {
    // return Native.SignedPreKeyRecord_GetId(this)
    return this._id
  }

  privateKey(): PrivateKey {
    // return PrivateKey._fromNativeHandle(Native.SignedPreKeyRecord_GetPrivateKey(this))
    return this._privKey
  }

  publicKey(): PublicKey {
    // return PublicKey._fromNativeHandle(Native.SignedPreKeyRecord_GetPublicKey(this))
    return this._pubKey
  }

  signature(): Uint8Array {
    // return Native.SignedPreKeyRecord_GetSignature(this)
    return this._signature
  }

  timestamp(): number {
    // return Native.SignedPreKeyRecord_GetTimestamp(this)
    return this._timestamp
  }
}

export class SignalMessage {
  private _messageVersion: number
  public messageProto: Uint8Array
  public macKey: Uint8Array
  readonly _nativeHandle: WhisperMessage // Native.SignalMessage

  private constructor(
    messageVersion: number,
    messageProto: Uint8Array,
    macKey: Uint8Array,
    handle: WhisperMessage // Native.SignalMessage
  ) {
    if ((messageVersion & 0xf) > 3 || messageVersion >> 4 < 3) {
      // min version > 3 or max version < 3
      throw new Error(`Incompatible version number on WhisperMessage ${messageVersion}`)
    }

    this._messageVersion = messageVersion
    this.messageProto = messageProto
    this.macKey = macKey
    this._nativeHandle = handle
  }

  static _new(
    messageVersion: number,
    macKey: Uint8Array,
    senderRatchetKey: PublicKey,
    counter: number,
    previousCounter: number,
    ciphertext: Uint8Array,
    senderIdentityKey: PublicKey,
    receiverIdentityKey: PublicKey
  ): SignalMessage {
    throw new Error('......SignalMessage')
    // return new SignalMessage(
    //   Native.SignalMessage_New(
    //     messageVersion,
    //     macKey,
    //     senderRatchetKey,
    //     counter,
    //     previousCounter,
    //     ciphertext,
    //     senderIdentityKey,
    //     receiverIdentityKey
    //   )
    // )
  }

  static deserialize(buffer: Uint8Array): SignalMessage {
    // return new SignalMessage(Native.SignalMessage_Deserialize(buffer))

    const version = buffer[0]!
    const messageProto = buffer.slice(1, buffer.byteLength - 8)
    const mac = buffer.slice(buffer.byteLength - 8, buffer.byteLength)

    return new SignalMessage(version, messageProto, mac, WhisperMessage.decode(messageProto))
  }

  body(): Uint8Array {
    throw new Error('......SignalMessage')
    // return Native.SignalMessage_GetBody(this)
  }

  counter(): number {
    throw new Error('......SignalMessage')
    // return Native.SignalMessage_GetCounter(this)
  }

  messageVersion(): number {
    throw new Error('......SignalMessage')
    // return Native.SignalMessage_GetMessageVersion(this)
  }

  serialize(): Uint8Array {
    throw new Error('......SignalMessage')
    // return Native.SignalMessage_GetSerialized(this)
  }

  verifyMac(
    senderIdentityKey: PublicKey,
    receivierIdentityKey: PublicKey,
    macKey: Uint8Array
  ): boolean {
    throw new Error('......SignalMessage')
    // return Native.SignalMessage_VerifyMac(this, senderIdentityKey, recevierIdentityKey, macKey)
  }
}

export class PreKeySignalMessage {
  private _messageVersion: number
  signalMessage: SignalMessage
  readonly _nativeHandle: PreKeyWhisperMessage // Native.PreKeySignalMessage

  private constructor(
    messageVersion: number,
    handle: PreKeyWhisperMessage // Native.PreKeySignalMessage
  ) {
    if ((messageVersion & 0xf) > 3 || messageVersion >> 4 < 3) {
      // min version > 3 or max version < 3
      throw new Error(`Incompatible version number on PreKeyWhisperMessage: ${messageVersion}`)
    }

    this._messageVersion = messageVersion
    this.signalMessage = SignalMessage.deserialize(handle.message)
    this._nativeHandle = handle
  }

  static _new(
    messageVersion: number,
    registrationId: number,
    preKeyId: number | null,
    signedPreKeyId: number,
    baseKey: PublicKey,
    identityKey: PublicKey,
    signalMessage: SignalMessage
  ): PreKeySignalMessage {
    throw new Error('......PreKeySignalMessage')
    // return new PreKeySignalMessage(
    //     Native.PreKeySignalMessage_New(
    //       messageVersion,
    //       registrationId,
    //       preKeyId,
    //       signedPreKeyId,
    //       baseKey,
    //       identityKey,
    //       signalMessage
    //     )
    //   )
  }

  static deserialize(buffer: Uint8Array): PreKeySignalMessage {
    // return new PreKeySignalMessage(Native.PreKeySignalMessage_Deserialize(buffer))

    const view = buffer
    const version = view[0]!
    const messageData = view.slice(1)

    return new PreKeySignalMessage(version, PreKeyWhisperMessage.decode(messageData))
  }

  preKeyId(): number | null {
    throw new Error('......PreKeySignalMessage')
    // return Native.PreKeySignalMessage_GetPreKeyId(this)
  }

  registrationId(): number {
    throw new Error('......PreKeySignalMessage')
    // return Native.PreKeySignalMessage_GetRegistrationId(this)
  }

  signedPreKeyId(): number {
    throw new Error('......PreKeySignalMessage')
    // return Native.PreKeySignalMessage_GetSignedPreKeyId(this)
  }

  version(): number {
    throw new Error('......PreKeySignalMessage')
    // return Native.PreKeySignalMessage_GetVersion(this)
  }

  serialize(): Uint8Array {
    throw new Error('......PreKeySignalMessage')
    // return Native.PreKeySignalMessage_Serialize(this)
  }
}

export { SessionRecord } from './session-record'

export abstract class SessionStore {
  // implements Native.SessionStore {
  // async _saveSession(name: Native.ProtocolAddress, record: Native.SessionRecord): Promise<void> {
  //   return this.saveSession(
  //     ProtocolAddress._fromNativeHandle(name),
  //     SessionRecord._fromNativeHandle(record)
  //   )
  // }

  // async _getSession(name: Native.ProtocolAddress): Promise<Native.SessionRecord | null> {
  //   const sess = await this.getSession(ProtocolAddress._fromNativeHandle(name))
  //   if (sess == null) {
  //     return null
  //   }
  //   return sess._nativeHandle
  // }

  abstract saveSession(name: ProtocolAddress, record: SessionRecord): Promise<void>

  abstract getSession(name: ProtocolAddress): Promise<SessionRecord | null>

  abstract getExistingSessions(addresses: ProtocolAddress[]): Promise<SessionRecord[]>
}

export abstract class IdentityKeyStore {
  // implements Native.IdentityKeyStore {
  // async _getIdentityKey(): Promise<Native.PrivateKey> {
  //   const key = await this.getIdentityKey()
  //   return key._nativeHandle
  // }

  // async _getLocalRegistrationId(): Promise<number> {
  //   return this.getLocalRegistrationId()
  // }

  // async _saveIdentity(name: Native.ProtocolAddress, key: Native.PublicKey): Promise<boolean> {
  //   return this.saveIdentity(
  //     ProtocolAddress._fromNativeHandle(name),
  //     PublicKey._fromNativeHandle(key)
  //   )
  // }

  // async _isTrustedIdentity(
  //   name: Native.ProtocolAddress,
  //   key: Native.PublicKey,
  //   sending: boolean
  // ): Promise<boolean> {
  //   const direction = sending ? Direction.Sending : Direction.Receiving

  //   return this.isTrustedIdentity(
  //     ProtocolAddress._fromNativeHandle(name),
  //     PublicKey._fromNativeHandle(key),
  //     direction
  //   )
  // }

  // async _getIdentity(name: Native.ProtocolAddress): Promise<Native.PublicKey | null> {
  //   const key = await this.getIdentity(ProtocolAddress._fromNativeHandle(name))
  //   if (key == null) {
  //     return Promise.resolve(null)
  //   }
  //   return key._nativeHandle
  // }

  abstract getIdentityKeyPair(): KeyPairType

  abstract getIdentityKey(): Promise<PrivateKey>

  abstract getLocalRegistrationId(): Promise<number>

  abstract saveIdentity(name: ProtocolAddress, key: PublicKey | Uint8Array): Promise<boolean>

  abstract isTrustedIdentity(
    name: ProtocolAddress,
    key: PublicKey | Uint8Array,
    direction: Direction
  ): Promise<boolean>

  abstract getIdentity(name: ProtocolAddress): Promise<PublicKey | null>
}

export abstract class PreKeyStore {
  // implements Native.PreKeyStore {
  // async _savePreKey(id: number, record: Native.PreKeyRecord): Promise<void> {
  //   return this.savePreKey(id, PreKeyRecord._fromNativeHandle(record))
  // }

  // async _getPreKey(id: number): Promise<Native.PreKeyRecord> {
  //   const pk = await this.getPreKey(id)
  //   return pk._nativeHandle
  // }

  // async _removePreKey(id: number): Promise<void> {
  //   return this.removePreKey(id)
  // }

  abstract savePreKey(id: number, record: PreKeyRecord): Promise<void>

  abstract getPreKey(id: number): Promise<PreKeyRecord>

  abstract removePreKey(id: number): Promise<void>
}

export abstract class SignedPreKeyStore {
  // implements Native.SignedPreKeyStore {
  // async _saveSignedPreKey(id: number, record: Native.SignedPreKeyRecord): Promise<void> {
  //   return this.saveSignedPreKey(id, SignedPreKeyRecord._fromNativeHandle(record))
  // }

  // async _getSignedPreKey(id: number): Promise<Native.SignedPreKeyRecord> {
  //   const pk = await this.getSignedPreKey(id)
  //   return pk._nativeHandle
  // }

  abstract saveSignedPreKey(id: number, record: SignedPreKeyRecord): Promise<void>

  abstract getSignedPreKey(id: number): Promise<SignedPreKeyRecord>
}

interface CiphertextMessageConvertible {
  asCiphertextMessage(): CiphertextMessage
}

export class CiphertextMessage {
  // readonly _nativeHandle: Native.CiphertextMessage

  // private constructor(nativeHandle: Native.CiphertextMessage) {
  //   this._nativeHandle = nativeHandle
  // }

  constructor(public message: MessageType) {}

  // static _fromNativeHandle(nativeHandle: Native.CiphertextMessage): CiphertextMessage {
  //   return new CiphertextMessage(nativeHandle)
  // }

  // static from(message: CiphertextMessageConvertible): CiphertextMessage {
  //   return message.asCiphertextMessage()
  // }

  serialize(): Buffer {
    // return Native.CiphertextMessage_Serialize(this)
    return Buffer.from(this.message.body!)
  }

  type(): number {
    // return Native.CiphertextMessage_Type(this)
    return this.message.type
  }
}

export class PlaintextContent implements CiphertextMessageConvertible {
  // readonly _nativeHandle: Native.PlaintextContent

  // private constructor(nativeHandle: Native.PlaintextContent) {
  //   this._nativeHandle = nativeHandle
  // }

  static deserialize(buffer: Uint8Array): PlaintextContent {
    throw new Error('......')
    // return new PlaintextContent(Native.PlaintextContent_Deserialize(buffer))
  }

  static from(message: DecryptionErrorMessage): PlaintextContent {
    throw new Error('......')
    // return new PlaintextContent(Native.PlaintextContent_FromDecryptionErrorMessage(message))
  }

  serialize(): Uint8Array {
    throw new Error('......')
    // return Native.PlaintextContent_Serialize(this)
  }

  body(): Uint8Array {
    throw new Error('......')
    // return Native.PlaintextContent_GetBody(this)
  }

  asCiphertextMessage(): CiphertextMessage {
    throw new Error('......')
    // return CiphertextMessage._fromNativeHandle(Native.CiphertextMessage_FromPlaintextContent(this))
  }
}

export class DecryptionErrorMessage {
  // readonly _nativeHandle: Native.DecryptionErrorMessage

  // private constructor(nativeHandle: Native.DecryptionErrorMessage) {
  //   this._nativeHandle = nativeHandle
  // }

  // static _fromNativeHandle(nativeHandle: Native.DecryptionErrorMessage): DecryptionErrorMessage {
  //   return new DecryptionErrorMessage(nativeHandle)
  // }

  static forOriginal(
    bytes: Uint8Array,
    type: CiphertextMessageType,
    timestamp: number,
    originalSenderDeviceId: number
  ): DecryptionErrorMessage {
    throw new Error('......')
    // return new DecryptionErrorMessage(
    //     Native.DecryptionErrorMessage_ForOriginalMessage(
    //       bytes,
    //       type,
    //       timestamp,
    //       originalSenderDeviceId
    //     )
    //   )
  }

  static deserialize(buffer: Uint8Array): DecryptionErrorMessage {
    throw new Error('......')
    // return new DecryptionErrorMessage(Native.DecryptionErrorMessage_Deserialize(buffer))
  }

  static extractFromSerializedBody(buffer: Uint8Array): DecryptionErrorMessage {
    throw new Error('......')
    // return new DecryptionErrorMessage(
    //     Native.DecryptionErrorMessage_ExtractFromSerializedContent(buffer)
    //   )
  }

  serialize(): Uint8Array {
    throw new Error('......')
    // return Native.DecryptionErrorMessage_Serialize(this)
  }

  timestamp(): number {
    throw new Error('......')
    // return Native.DecryptionErrorMessage_GetTimestamp(this)
  }

  deviceId(): number {
    throw new Error('......')
    // return Native.DecryptionErrorMessage_GetDeviceId(this)
  }

  ratchetKey(): PublicKey | undefined {
    throw new Error('......')
    // const keyHandle = Native.DecryptionErrorMessage_GetRatchetKey(this)
    //   if (keyHandle) {
    //     return PublicKey._fromNativeHandle(keyHandle)
    //   }
    //   return undefined
  }
}

export async function processPreKeyBundle(
  bundle: PreKeyBundle,
  address: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore
): Promise<void> {
  // return Native.SessionBuilder_ProcessPreKeyBundle(
  //   bundle,
  //   address,
  //   sessionStore,
  //   identityStore,
  //   null
  // )

  const sessionBuilder = new SessionBuilder(sessionStore, identityStore, address)
  await sessionBuilder.processPreKey({
    registrationId: bundle.registrationId(),
    identityKey: bundle.identityKey().value,
    signedPreKey: {
      keyId: bundle.signedPreKeyId(),
      publicKey: bundle.signedPreKeyPublic().value,
      signature: bundle.signedPreKeySignature(),
    },
    preKey: {
      keyId: bundle.preKeyId(),
      publicKey: bundle.preKeyPublic()?.value,
    },
  })
}

export async function signalEncrypt(
  message: ArrayBuffer,
  address: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore
): Promise<CiphertextMessage> {
  // return CiphertextMessage._fromNativeHandle(
  //   await Native.SessionCipher_EncryptMessage(message, address, sessionStore, identityStore, null)
  // )

  const sessionCipher = new SessionCipher(sessionStore, identityStore, address)
  return new CiphertextMessage(await sessionCipher.encrypt(message))
}

export async function signalDecrypt(
  message: SignalMessage,
  address: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore
): Promise<ArrayBuffer> {
  const sessionCipher = new SessionCipher(sessionStore, identityStore, address)
  return await sessionCipher.decryptWhisperMessage(message)
}

export async function signalDecryptPreKey(
  message: PreKeySignalMessage,
  address: ProtocolAddress,
  sessionStore: SessionStore,
  identityStore: IdentityKeyStore,
  prekeyStore: PreKeyStore,
  signedPrekeyStore: SignedPreKeyStore
): Promise<ArrayBuffer> {
  const sessionCipher = new SessionCipher(sessionStore, identityStore, address)
  return await sessionCipher.decryptPreKeyWhisperMessage(prekeyStore, signedPrekeyStore, message)
  
}
