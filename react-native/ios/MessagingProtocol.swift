//
//  Ready
//
//  Created by Thang Nguyen on 6/22/23.
//

import LibMessagingClient

@objc(MessagingProtocol)
class MessagingProtocol: NSObject {
  let TAG = "MessagingProtocol"
  
  @objc
  static func requiresMainQueueSetup() -> Bool {
    // If your module does not require access to UIKit, then you should respond to + requiresMainQueueSetup with NO.
    return false
  }
  
  // @objc
  // func constantsToExport() -> [String: Any]! {
  //   return ["someKey": "someValue"]
  // }
  
  @objc
  func createKeyPair(_ rawPrivateKey: Array<UInt8>?,
                     resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
    do {
      let privateKey: PrivateKey
      if rawPrivateKey != nil {
        privateKey = try PrivateKey.init(rawPrivateKey!)
      } else {
        privateKey = PrivateKey.generate()
      }
      let publicKey = privateKey.publicKey
      resolve([privateKey.serialize(), publicKey.serialize()])
    } catch {
      Log.e(TAG, "createKeyPair ERROR:", error)
      reject("createKeyPair_failure", "\(error)", error)
    }
  }
  
  @objc
  func privateKeySign(_ rawPrivateKey: Array<UInt8>, data: Array<UInt8>,
                      resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
    do {
      let privateKey = try PrivateKey.init(rawPrivateKey)
      resolve(privateKey.generateSignature(message: data))
    } catch {
      Log.e(TAG, "privateKeySign ERROR:", error)
      reject("privateKeySign_failure", "\(error)", error)
    }
  }
  
  @objc
  func privateKeyAgreeWithOtherPublicKey(_ rawPrivateKey: Array<UInt8>, publicKey rawPublicKey: Array<UInt8>,
                                         resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
    do {
      let privateKey = try PrivateKey.init(rawPrivateKey)
      let publicKey = try PublicKey.init(rawPublicKey)
      resolve(privateKey.keyAgreement(with: publicKey))
    } catch {
      Log.e(TAG, "privateKeyAgreeWithOtherPublicKey ERROR:", error)
      reject("privateKeyAgreementWithOtherPublicKey_failure", "\(error)", error)
    }
  }
  
  @objc
  func verifySignature(_ rawPublicKey: Array<UInt8>, data: Array<UInt8>, signature: Array<UInt8>,
                       resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
    do {
      let publicKey = try PublicKey.init(rawPublicKey)
      resolve(try publicKey.verifySignature(message: data, signature: signature))
    } catch {
      Log.e(TAG, "verifySignature ERROR:", error)
      reject("verifySignature_failure", "\(error)", error)
    }
  }
  
  @objc
  func HKDF(_ inputKeyMaterial: Array<UInt8>, salt: Array<UInt8>?, info: Array<UInt8>,
            resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
    // owsAssertDebug(!Thread.isMainThread)
    
    do {
      let hkdf = try hkdf(outputLength: 80, inputKeyMaterial: inputKeyMaterial, salt: salt ?? [], info: info)
      resolve([Array(hkdf[..<32]), Array(hkdf[32..<64]), Array(hkdf[64...])])
    } catch {
      Log.e(TAG, "HKDF ERROR:", error)
      reject("HKDF_failure", "\(error)", error)
    }
  }
  
  @objc
  func computeMac(_ macKey: Array<UInt8>, data: Array<UInt8>, // chunkSize: UInt32,
                  resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
    // owsAssertDebug(!Thread.isMainThread)
    
    do {
      // let mac = try IncrementalMacContext(key: macKey, chunkSize: .bytes(chunkSize <= 0 ? 32 : chunkSize))
      // try mac.update(data)
      // resolve(try mac.finalize())
      
      resolve(try LibMessagingClient.computeMac(macKey: macKey, data: data))
    } catch {
      Log.e(TAG, "computeMac ERROR:", error)
      reject("computeMac_failure", "\(error)", error)
    }
  }
  
  @objc
  func verifyMac(_ data: Array<UInt8>, macKey: Array<UInt8>, mac: Array<UInt8>, length: UInt32,
                 resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
    // owsAssertDebug(!Thread.isMainThread)
    
    do {
      resolve(try LibMessagingClient.verifyMac(macKey: macKey, data: data, mac: mac, length: length))
    } catch {
      Log.e(TAG, "verifyMac ERROR:", error)
      reject("verifyMac_failure", "\(error)", error)
    }
  }
  
  @objc
  func encrypt(_ key: Array<UInt8>, data: Array<UInt8>, iv: Array<UInt8>,
               resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
    // owsAssertDebug(!Thread.isMainThread)
    
    do {
      resolve(try signalEncryptData(key: key, data: data, iv: iv))
    } catch {
      Log.e(TAG, "encrypt ERROR:", error)
      reject("encrypt_failure", "\(error)", error)
    }
  }
  
  @objc
  func decrypt(_ key: Array<UInt8>, data: Array<UInt8>, iv: Array<UInt8>,
               resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
    // owsAssertDebug(!Thread.isMainThread)
    
    do {
      resolve(try signalDecryptData(key: key, data: data, iv: iv))
    } catch {
      Log.e(TAG, "decrypt ERROR:", error)
      reject("decrypt_failure", "\(error)", error)
    }
  }
}
