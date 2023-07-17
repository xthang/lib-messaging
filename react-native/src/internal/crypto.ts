/* eslint-disable no-param-reassign */
/* eslint-disable no-plusplus */
/* eslint-disable no-bitwise */

import cryptoMobile from 'crypto'
import * as util from '../helpers'
import MessagingProtocolModule from '../Native'
import { type KeyPairType } from '../types'

function arrayBufferToArray(value: ArrayBuffer) {
  return Array.from(new Uint8Array(value))
}

function toArrayBuffer(value: string | Iterable<number>) {
  let buf: ArrayBufferLike
  if (typeof value === 'string') {
    buf = util.fromUtf8ToArray(value).buffer
  } else {
    buf = new Uint8Array(value).buffer
  }
  return buf
}

function toNodeBuffer(value: Iterable<number> | ArrayLike<number> | ArrayBufferLike) {
  return Buffer.from(new Uint8Array(value))
}

// -----------------------------

export async function encrypt(
  key: ArrayBuffer,
  data: ArrayBuffer,
  iv: ArrayBuffer
): Promise<ArrayBuffer> {
  // const impkey = await this._webcrypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, [
  //   'encrypt',
  // ])

  // return this._webcrypto.subtle.encrypt({ name: 'AES-CBC', iv: new Uint8Array(iv) }, impkey, data)

  const nodeData = toNodeBuffer(data)
  const nodeIv = toNodeBuffer(iv)
  const nodeKey = toNodeBuffer(key)
  const cipher = cryptoMobile.createCipheriv('aes-256-cbc', nodeKey, nodeIv)
  const encBuf = Buffer.concat([cipher.update(nodeData), cipher.final()])
  return Promise.resolve(toArrayBuffer(encBuf))

  // const encBuf = await MessagingProtocolModule.encrypt(
  //   arrayBufferToArray(key),
  //   arrayBufferToArray(data),
  //   arrayBufferToArray(iv)
  // )
  // return toArrayBuffer(encBuf)
}

export async function decrypt(
  key: ArrayBuffer,
  data: ArrayBuffer,
  iv: ArrayBuffer
): Promise<ArrayBuffer> {
  // const impkey = await this._webcrypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, [
  //   'decrypt',
  // ])

  // return this._webcrypto.subtle.decrypt({ name: 'AES-CBC', iv: new Uint8Array(iv) }, impkey, data)

  // const nodeData = toNodeBuffer(data)
  // const nodeIv = toNodeBuffer(iv)
  // const nodeKey = toNodeBuffer(key)
  // const decipher = cryptoMobile.createDecipheriv('aes-256-cbc', nodeKey, nodeIv)
  // const decBuf = Buffer.concat([decipher.update(nodeData), decipher.final()])
  // return Promise.resolve(toArrayBuffer(decBuf))

  const decBuf = await MessagingProtocolModule.decrypt(
    arrayBufferToArray(key),
    arrayBufferToArray(data),
    arrayBufferToArray(iv)
  )
  return new Uint8Array(decBuf)
}

export async function sign(key: ArrayBuffer, data: ArrayBuffer): Promise<ArrayBuffer> {
  // const impkey = await this._webcrypto.subtle.importKey(
  //   'raw',
  //   key,
  //   { name: 'HMAC', hash: { name: 'SHA-256' } },
  //   false,
  //   ['sign']
  // )

  // // eslint-disable-next-line no-useless-catch
  // try {
  //   return this._webcrypto.subtle.sign({ name: 'HMAC', hash: 'SHA-256' }, impkey, data)
  // } catch (e) {
  //   // console.log({ e, data, impkey })
  //   throw e
  // }

  // TODO: fix `.update(data)`. The arg type is incorrect. And it generates the same hmac as when we call `.update(new ArrayBuffer(0))`
  const mac = cryptoMobile.createHmac('sha256', util.fromBufferToB64(key)).update(new Uint8Array(data)).digest()
  // const mac = await MessagingProtocolModule.computeMac(
  //   Array.from(new TextEncoder().encode(Utils.fromBufferToB64(key))),
  //   arrayBufferToArray(data)
  // )
  return toArrayBuffer(mac)
}

export async function verifyMAC(
  data: ArrayBuffer,
  key: ArrayBuffer,
  mac: ArrayBuffer,
  length: number
): Promise<void> {
  const calculatedMac = await sign(key, data)
  if (mac.byteLength !== length || calculatedMac.byteLength < length) {
    throw new Error('Bad MAC length!')
  }
  const a = new Uint8Array(calculatedMac)
  const b = new Uint8Array(mac)
  let result = 0
  for (let i = 0; i < mac.byteLength; ++i) {
    result |= a[i]! ^ b[i]!
  }
  if (result !== 0) {
    throw new Error(`Bad MAC!`)
  }

  // await MessagingProtocolModule.verifyMac(
  //   arrayBufferToArray(data),
  //   arrayBufferToArray(key),
  //   arrayBufferToArray(mac),
  //   length
  // )
}

// async hash(data: ArrayBuffer): Promise<ArrayBuffer> {
//   // return this._webcrypto.subtle.digest({ name: 'SHA-512' }, data)

//   const nodeValue = toNodeValue(data)
//   const hash = this._webcrypto.createHash('sha512')
//   hash.update(nodeValue)
//   return Promise.resolve(toArrayBuffer(hash.digest()))
// }

// Curve25519 crypto

export async function createKeyPair(privKey?: ArrayBuffer): Promise<KeyPairType> {
  // if (!privKey) {
  //   privKey = getRandomBytes(32)
  // }
  // return _curve.createKeyPair(privKey)

  const rawKeyPair = await MessagingProtocolModule.createKeyPair(
    privKey ? arrayBufferToArray(privKey) : null
  )

  // prepend version byte
  // const origPub = new Uint8Array(rawKeyPair[1])
  // const pub = new Uint8Array(33)
  // pub.set(origPub, 1)
  // pub[0] = 5

  return {
    privKey: toArrayBuffer(rawKeyPair[0]!),
    pubKey: toArrayBuffer(rawKeyPair[1]!),
  }
}

export async function ECDHE(pubKey: ArrayBuffer, privKey: ArrayBuffer): Promise<ArrayBuffer> {
  // return _curve.ECDHE(pubKey, privKey)

  let pubKeyArray: Uint8Array
  if (pubKey.byteLength === 32) {
    pubKeyArray = new Uint8Array(33)
    pubKeyArray.set(new Uint8Array(pubKey), 1)
    pubKeyArray[0] = 5
  } else {
    pubKeyArray = new Uint8Array(pubKey)
  }
  const sharedSecret = await MessagingProtocolModule.privateKeyAgreeWithOtherPublicKey(
    arrayBufferToArray(privKey),
    Array.from(pubKeyArray)
  )
  return toArrayBuffer(sharedSecret)
}

export async function Ed25519Sign(
  privKey: ArrayBuffer,
  message: ArrayBuffer
): Promise<ArrayBuffer> {
  // return _curve.Ed25519Sign(privKey, message)

  return toArrayBuffer(
    await MessagingProtocolModule.privateKeySign(
      arrayBufferToArray(privKey),
      arrayBufferToArray(message)
    )
  )
}

export async function Ed25519Verify(
  pubKey: ArrayBuffer,
  msg: ArrayBuffer,
  sig: ArrayBuffer
): Promise<void> {
  // _curve.Ed25519Verify(pubKey, msg, sig)

  const verifyResult = await MessagingProtocolModule.verifySignature(
    arrayBufferToArray(pubKey),
    arrayBufferToArray(msg),
    arrayBufferToArray(sig)
  )
  if (!verifyResult) {
    throw new Error('Invalid signature (AsyncCurve)')
  }
}

// HKDF for TextSecure has a bit of additional handling - salts always end up being 32 bytes
export async function HKDF(
  input: ArrayBuffer,
  salt: ArrayBuffer,
  info: string
): Promise<ArrayBuffer[]> {
  if (salt && salt.byteLength !== 32) {
    throw new Error('Got salt of incorrect length')
  }

  const abInfo = util.binaryStringToArrayBuffer(info)
  if (!abInfo) {
    throw new Error(`Invalid HKDF info`)
  }

  const PRK = await sign(salt, input)
  const infoBuffer = new ArrayBuffer(abInfo.byteLength + 1 + 32)
  const infoArray = new Uint8Array(infoBuffer)
  infoArray.set(new Uint8Array(abInfo), 32)
  infoArray[infoArray.length - 1] = 1
  const T1 = await sign(PRK, infoBuffer.slice(32))
  infoArray.set(new Uint8Array(T1))
  infoArray[infoArray.length - 1] = 2
  const T2 = await sign(PRK, infoBuffer)
  infoArray.set(new Uint8Array(T2))
  infoArray[infoArray.length - 1] = 3
  const T3 = await sign(PRK, infoBuffer)
  return [T1, T2, T3]

  // const keys = await MessagingProtocolModule.HKDF(
  //   arrayBufferToArray(input),
  //   salt ? arrayBufferToArray(salt) : null,
  //   arrayBufferToArray(abInfo)
  // )
  // return keys.map(toArrayBuffer)
}
