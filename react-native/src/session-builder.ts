/* eslint-disable no-param-reassign */
/* eslint-disable no-plusplus */
/* eslint-disable lines-between-class-members */

import { PreKeyWhisperMessage } from '@privacyresearch/libsignal-protocol-protobuf-ts'
import * as base64 from 'base64-js'

import { ProtocolAddress } from './Address'
import { uint8ArrayToArrayBuffer } from './helpers'
import * as Internal from './internal'
import { SessionRecord } from './session-record'
import { type SessionType, BaseKeyType, ChainType, type DeviceType } from './session-types'
import { type KeyPairType } from './types'
import { Direction, IdentityKeyStore, PreKeyStore, SessionStore, SignedPreKeyStore } from './index'

export class SessionBuilder {
  remoteAddress: ProtocolAddress

  sessionStore: SessionStore
  identityStore: IdentityKeyStore

  constructor(
    sessionStore: SessionStore,
    identityStore: IdentityKeyStore,
    remoteAddress: ProtocolAddress
  ) {
    this.remoteAddress = remoteAddress
    this.sessionStore = sessionStore
    this.identityStore = identityStore
  }

  processPreKeyJob = async (device: DeviceType): Promise<SessionType> => {
    const trusted = await this.identityStore.isTrustedIdentity(
      this.remoteAddress,
      device.identityKey,
      Direction.Sending
    )
    if (!trusted) {
      throw new Error('Identity key changed')
    }

    // This will throw if invalid
    await Internal.crypto.Ed25519Verify(
      device.identityKey,
      device.signedPreKey.publicKey,
      device.signedPreKey.signature
    )

    const ephemeralKey = await Internal.crypto.createKeyPair()

    const deviceOneTimePreKey = device.preKey?.publicKey

    const session = await this.startSessionAsInitiator(
      ephemeralKey,
      device.identityKey,
      device.signedPreKey.publicKey,
      deviceOneTimePreKey,
      device.registrationId
    )
    session.pendingPreKey = {
      signedKeyId: device.signedPreKey.keyId,
      baseKey: ephemeralKey.pubKey,
    }
    if (device.preKey) {
      session.pendingPreKey.preKeyId = device.preKey.keyId
    }
    const address = this.remoteAddress
    let record = await this.sessionStore.getSession(address)
    if (!record) {
      record = new SessionRecord(device.registrationId)
    }

    record.archiveCurrentState()
    record.updateSessionState(session)
    await Promise.all([
      this.sessionStore.saveSession(address, record),
      this.identityStore.saveIdentity(
        this.remoteAddress,
        Buffer.from(session.indexInfo.remoteIdentityKey)
      ),
    ])

    return session
  }

  // Arguments map to the X3DH spec: https://signal.org/docs/specifications/x3dh/#keys
  // We are Alice the initiator.
  startSessionAsInitiator = async (
    EKa: KeyPairType<ArrayBuffer>,
    IKb: ArrayBuffer,
    SPKb: ArrayBuffer,
    OPKb: ArrayBuffer | undefined,
    registrationId?: number
  ): Promise<SessionType> => {
    const IKa = this.identityStore.getIdentityKeyPair()

    if (!IKa) {
      throw new Error(`No identity key. Cannot initiate session.`)
    }

    let sharedSecret: Uint8Array
    if (OPKb === undefined) {
      sharedSecret = new Uint8Array(32 * 4)
    } else {
      sharedSecret = new Uint8Array(32 * 5)
    }

    // As specified in X3DH spec secion 22, the first 32 bytes are
    // 0xFF for curve25519 (https://signal.org/docs/specifications/x3dh/#cryptographic-notation)
    for (let i = 0; i < 32; i++) {
      sharedSecret[i] = 0xff
    }

    if (!SPKb) {
      throw new Error(`theirSignedPubKey is undefined. Cannot proceed with ECDHE`)
    }

    // X3DH Section 3.3. https://signal.org/docs/specifications/x3dh/
    // We'll handle the possible one-time prekey below
    const ecRes = await Promise.all([
      Internal.crypto.ECDHE(SPKb, IKa.privKey),
      Internal.crypto.ECDHE(IKb, EKa.privKey),
      Internal.crypto.ECDHE(SPKb, EKa.privKey),
    ])

    sharedSecret.set(new Uint8Array(ecRes[0]), 32)
    sharedSecret.set(new Uint8Array(ecRes[1]), 32 * 2)

    sharedSecret.set(new Uint8Array(ecRes[2]), 32 * 3)

    if (OPKb) {
      const ecRes4 = await Internal.crypto.ECDHE(OPKb, EKa.privKey)
      sharedSecret.set(new Uint8Array(ecRes4), 32 * 4)
    }

    const masterKey = await Internal.crypto.HKDF(
      uint8ArrayToArrayBuffer(sharedSecret),
      new ArrayBuffer(32),
      'WhisperText'
    )

    const session: SessionType = {
      registrationId,
      currentRatchet: {
        rootKey: masterKey[0]!,
        lastRemoteEphemeralKey: SPKb,
        previousCounter: 0,
      },
      indexInfo: {
        remoteIdentityKey: IKb,
        closed: -1,
      },
      oldRatchetList: [],
      chains: {},
    }

    // We're initiating so we go ahead and set our first sending ephemeral key now,
    // otherwise we figure it out when we first maybeStepRatchet with the remote's ephemeral key

    session.indexInfo.baseKey = EKa.pubKey
    session.indexInfo.baseKeyType = BaseKeyType.OURS
    const ourSendingEphemeralKey = await Internal.crypto.createKeyPair()
    session.currentRatchet.ephemeralKeyPair = ourSendingEphemeralKey

    await this.calculateSendingRatchet(session, SPKb)

    return session
  }

  // Arguments map to the X3DH spec: https://signal.org/docs/specifications/x3dh/#keys
  // We are Bob now.
  startSessionWthPreKeyMessage = async (
    OPKb: KeyPairType<ArrayBuffer> | undefined,
    SPKb: KeyPairType<ArrayBuffer>,
    message: PreKeyWhisperMessage
  ): Promise<SessionType> => {
    const IKb = this.identityStore.getIdentityKeyPair()
    const IKa = message.identityKey
    const EKa = message.baseKey

    if (!IKb) {
      throw new Error(`No identity key. Cannot initiate session.`)
    }

    let sharedSecret: Uint8Array
    if (!OPKb) {
      sharedSecret = new Uint8Array(32 * 4)
    } else {
      sharedSecret = new Uint8Array(32 * 5)
    }

    // As specified in X3DH spec secion 22, the first 32 bytes are
    // 0xFF for curve25519 (https://signal.org/docs/specifications/x3dh/#cryptographic-notation)
    for (let i = 0; i < 32; i++) {
      sharedSecret[i] = 0xff
    }

    // X3DH Section 3.3. https://signal.org/docs/specifications/x3dh/
    // We'll handle the possible one-time prekey below
    const ecRes = await Promise.all([
      Internal.crypto.ECDHE(IKa, SPKb.privKey),
      Internal.crypto.ECDHE(EKa, IKb.privKey),
      Internal.crypto.ECDHE(EKa, SPKb.privKey),
    ])

    sharedSecret.set(new Uint8Array(ecRes[0]), 32)
    sharedSecret.set(new Uint8Array(ecRes[1]), 32 * 2)
    sharedSecret.set(new Uint8Array(ecRes[2]), 32 * 3)

    if (OPKb) {
      const ecRes4 = await Internal.crypto.ECDHE(EKa, OPKb.privKey)
      sharedSecret.set(new Uint8Array(ecRes4), 32 * 4)
    }

    const masterKey = await Internal.crypto.HKDF(
      uint8ArrayToArrayBuffer(sharedSecret),
      new ArrayBuffer(32),
      'WhisperText'
    )

    const session: SessionType = {
      registrationId: message.registrationId,
      currentRatchet: {
        rootKey: masterKey[0]!,
        lastRemoteEphemeralKey: EKa,
        previousCounter: 0,
      },
      indexInfo: {
        remoteIdentityKey: IKa,
        closed: -1,
      },
      oldRatchetList: [],
      chains: {},
    }

    // If we're initiating we go ahead and set our first sending ephemeral key now,
    // otherwise we figure it out when we first maybeStepRatchet with the remote's ephemeral key

    session.indexInfo.baseKey = EKa
    session.indexInfo.baseKeyType = BaseKeyType.THEIRS
    session.currentRatchet.ephemeralKeyPair = SPKb

    return session
  }

  async calculateSendingRatchet(session: SessionType, remoteKey: ArrayBuffer): Promise<void> {
    const ratchet = session.currentRatchet
    if (!ratchet.ephemeralKeyPair) {
      throw new Error(`Invalid ratchet - ephemeral key pair is missing`)
    }

    const ephPrivKey = ratchet.ephemeralKeyPair.privKey
    const rootKey = ratchet.rootKey
    const ephPubKey = base64.fromByteArray(new Uint8Array(ratchet.ephemeralKeyPair.pubKey))
    if (!(ephPrivKey && ephPubKey && rootKey)) {
      throw new Error(`Missing key, cannot calculate sending ratchet`)
    }
    const sharedSecret = await Internal.crypto.ECDHE(remoteKey, ephPrivKey)
    const masterKey = await Internal.crypto.HKDF(sharedSecret, rootKey, 'WhisperRatchet')

    session.chains[ephPubKey] = {
      messageKeys: {},
      chainKey: { counter: -1, key: masterKey[1] },
      chainType: ChainType.SENDING,
    }
    ratchet.rootKey = masterKey[0]!
  }

  async processPreKey(device: DeviceType): Promise<SessionType> {
    // return this.processPreKeyJob(device)
    const runJob = async () => {
      const sess = await this.processPreKeyJob(device)
      return sess
    }
    // return SessionLock.queueJobForNumber(this.remoteAddress.toString(), runJob)
    return runJob()
  }

  async processV3(
    prekeyStore: PreKeyStore,
    signedPrekeyStore: SignedPreKeyStore,
    record: SessionRecord,
    message: PreKeyWhisperMessage
  ): Promise<number | undefined> {
    const trusted = this.identityStore.isTrustedIdentity(
      this.remoteAddress,
      Buffer.from(message.identityKey),
      Direction.Receiving
    )
    if (!trusted) {
      throw new Error(`Unknown identity key: ${uint8ArrayToArrayBuffer(message.identityKey)}`)
    }

    const [preKeyPair, signedPreKeyPair] = await Promise.all([
      prekeyStore.getPreKey(message.preKeyId),
      signedPrekeyStore.getSignedPreKey(message.signedPreKeyId),
    ])

    if (record.getSessionByBaseKey(message.baseKey)) {
      return undefined
    }

    const session = record.getOpenSession()

    if (signedPreKeyPair === undefined) {
      // Session may or may not be the right one, but if its not, we
      // can't do anything about it ...fall through and let
      // decryptWhisperMessage handle that case
      if (session && session.currentRatchet) {
        return undefined
      }
      throw new Error('Missing Signed PreKey for PreKeyWhisperMessage')
    }

    if (session) {
      record.archiveCurrentState()
    }
    if (message.preKeyId && !preKeyPair) {
      // console.log('Invalid prekey id', message.preKeyId)
    }

    const new_session = await this.startSessionWthPreKeyMessage(
      {
        privKey: preKeyPair.privateKey().value.buffer,
        pubKey: preKeyPair.publicKey().value.buffer,
      },
      {
        privKey: signedPreKeyPair.privateKey().value.buffer,
        pubKey: signedPreKeyPair.publicKey().value.buffer,
      },
      message
    )
    record.updateSessionState(new_session)
    await this.identityStore.saveIdentity(this.remoteAddress, Buffer.from(message.identityKey))

    return message.preKeyId
  }
}
