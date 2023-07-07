//
//  Ready
//
//  Created by Thang Nguyen on 6/22/23.
//

#import <React/RCTBridgeModule.h>
//#import "RTNMessagingProtocolSpec.h"

@interface RCT_EXTERN_MODULE(MessagingProtocol, NSObject<RCTBridgeModule>)
//@interface RCT_EXTERN_MODULE(MessagingProtocol, NSObject<NativeSpec>)
//@interface RCT_EXTERN_REMAP_MODULE(CalendarModule, CalendarManager, NSObject)

RCT_EXTERN_METHOD(createKeyPair:(NSArray * _Nullable)privateKey
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(privateKeySign:(NSArray * _Nonnull)privateKey
                  data:(NSArray * _Nonnull)data
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(privateKeyAgreeWithOtherPublicKey:(NSArray * _Nonnull)privateKey
                  publicKey:(NSArray * _Nonnull)publicKey
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verifySignature:(NSArray * _Nonnull)publicKey
                  data:(NSArray * _Nonnull)data
                  signature:(NSArray * _Nonnull)signature
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(HKDF:(NSArray * _Nonnull)inputKeyMaterial
                  salt:(NSArray * _Nullable)salt
                  info:(NSArray * _Nonnull)info
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(computeMac:(NSArray * _Nonnull)macKey
                  data:(NSArray * _Nonnull)data
                  // chunkSize: (NSNumber)chunkSize
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verifyMac:(NSArray * _Nonnull)data
                  macKey:(NSArray * _Nonnull)macKey
                  mac:(NSArray * _Nonnull)mac
                  length: (NSNumber)length
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(encrypt:(NSArray * _Nonnull)key
                  data:(NSArray * _Nonnull)data
                  iv:(NSArray * _Nonnull)iv
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(decrypt:(NSArray * _Nonnull)key
                  data:(NSArray * _Nonnull)data
                  iv:(NSArray * _Nonnull)iv
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

@end
