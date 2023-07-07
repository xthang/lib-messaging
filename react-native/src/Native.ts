import { NativeModules, Platform } from 'react-native'
// import { TurboModuleRegistry } from 'react-native'
// import type { TurboModule } from 'react-native/Libraries/TurboModule/RCTExport'

const LINKING_ERROR =
  `The package 'lib-messaging' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n'

const MessagingProtocol =
  NativeModules.MessagingProtocol ??
  new Proxy(
    {},
    {
      get() {
        throw new Error(LINKING_ERROR)
      },
    }
  )

interface MessagingProtocolModule {
  getConstants: () => Record<string, any>
  // /** @deprecated This will no longer be supported with TurboModules, so we encourage the community to switch to the above approach to avoid necessary migration down the line. */
  // constantsToExport: () => Record<string, any>

  // PrivateKey_Generate(): Promise<Array<number>>
  createKeyPair(privateKey: Array<number> | null): Promise<Array<number>[]>
  privateKeySign(privateKey: Array<number>, data: Array<number>): Promise<Array<number>>
  privateKeyAgreeWithOtherPublicKey( // sharedSecret
    privateKey: Array<number>,
    publicKey: Array<number>
  ): Promise<Array<number>>
  verifySignature(
    publicKey: Array<number>,
    data: Array<number>,
    signature: Array<number>
  ): Promise<boolean>

  HKDF(
    inputKeyMaterial: Array<number>,
    salt: Array<number> | null,
    info: Array<number>
  ): Promise<Array<number>[]>

  computeMac(macKey: Array<number>, data: Array<number>): Promise<Array<number>>
  verifyMac(
    data: Array<number>,
    key: Array<number>,
    mac: Array<number>,
    length: number
  ): Promise<Array<number>>

  encrypt(key: Array<number>, data: Array<number>, iv: Array<number>): Promise<Array<number>>
  decrypt(key: Array<number>, data: Array<number>, iv: Array<number>): Promise<Array<number>>
}

export default MessagingProtocol as MessagingProtocolModule

// export interface Spec extends TurboModule {
// }

// export default TurboModuleRegistry.get<Spec>('MessagingProtocol')
