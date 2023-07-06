//
// Copyright 2023 Ready.io
//

import MessagingFfi
import Foundation

public class PrivateKey: ClonableHandleOwner {
    public convenience init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBorrowedBuffer {
            var result: OpaquePointer?
            try checkError(msg_privatekey_deserialize(&result, $0))
            return result
        }
        self.init(owned: handle!)
    }

    public static func generate() -> PrivateKey {
        return failOnError {
            try invokeFnReturningNativeHandle {
                msg_privatekey_generate($0)
            }
        }
    }

    internal override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> MsgFfiErrorRef? {
        return msg_privatekey_clone(&newHandle, currentHandle)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> MsgFfiErrorRef? {
        return msg_privatekey_destroy(handle)
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    msg_privatekey_serialize($0, nativeHandle)
                }
            }
        }
    }

    public func generateSignature<Bytes: ContiguousBytes>(message: Bytes) -> [UInt8] {
        return withNativeHandle { nativeHandle in
            message.withUnsafeBorrowedBuffer { messageBuffer in
                failOnError {
                    try invokeFnReturningArray {
                        msg_privatekey_sign($0, nativeHandle, messageBuffer)
                    }
                }
            }
        }
    }

    public func keyAgreement(with other: PublicKey) -> [UInt8] {
        return withNativeHandles(self, other) { nativeHandle, otherHandle in
            failOnError {
                try invokeFnReturningArray {
                    msg_privatekey_agree($0, nativeHandle, otherHandle)
                }
            }
        }
    }

    public var publicKey: PublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    msg_privatekey_get_public_key($0, nativeHandle)
                }
            }
        }
    }

}
