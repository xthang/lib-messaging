//
// Copyright 2023 Ready.io
//

import Foundation
import MessagingFfi

public func computeMac<Bytes: ContiguousBytes>(macKey: Bytes, data: Bytes) throws -> [UInt8] {
    return try data.withUnsafeBorrowedBuffer { dataBuffer in
        try macKey.withUnsafeBorrowedBuffer { macKeyBuffer in
            try invokeFnReturningArray {
                msg_compute_mac($0, macKeyBuffer, dataBuffer)
            }
        }
    }
}

public func verifyMac<Bytes: ContiguousBytes>(macKey: Bytes, data: Bytes, mac: Bytes, length: UInt32) throws -> Bool {
    return try data.withUnsafeBorrowedBuffer { dataBuffer in
        try macKey.withUnsafeBorrowedBuffer { macKeyBuffer in
            try mac.withUnsafeBorrowedBuffer { macBuffer in
                var result: Bool = false
                try checkError(msg_verify_mac(&result,
                                              macKeyBuffer,
                                              dataBuffer,
                                              macBuffer,
                                              length))
                return result
            }
        }
    }
}
