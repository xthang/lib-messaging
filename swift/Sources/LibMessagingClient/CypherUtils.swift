//
// Copyright 2023 Ready.io
//

import MessagingFfi
import Foundation

public func signalEncryptData<Bytes: ContiguousBytes>(key: Bytes, data: Bytes, iv: Bytes) throws -> [UInt8] {
    return try key.withUnsafeBorrowedBuffer { keyBuffer in
        try data.withUnsafeBorrowedBuffer { dataBuffer in
            try iv.withUnsafeBorrowedBuffer { ivBuffer in
                try invokeFnReturningArray {
                    msg_aes256_cbc_encrypt($0, dataBuffer, keyBuffer, ivBuffer)
                }
            }
        }
    }
}

public func signalDecryptData<Bytes: ContiguousBytes>(key: Bytes, data: Bytes, iv: Bytes) throws -> [UInt8] {
    return try key.withUnsafeBorrowedBuffer { keyBuffer in
        try data.withUnsafeBorrowedBuffer { dataBuffer in
            try iv.withUnsafeBorrowedBuffer { ivBuffer in
                try invokeFnReturningArray {
                    msg_aes256_cbc_decrypt($0, dataBuffer, keyBuffer, ivBuffer)
                }
            }
        }
    }
}
