export interface KeyPairType<T = ArrayBuffer> {
  pubKey: T
  privKey: T
}

export interface PreKeyType<T = ArrayBuffer> {
  keyId: number
  publicKey: T
}

export interface SignedPublicPreKeyType<T = ArrayBuffer> extends PreKeyType<T> {
  signature: T
}
