//
// Copyright 2023 Ready.io
//

import MessagingFfi
import Foundation

#if canImport(SignalCoreKit)
import SignalCoreKit
#endif

public enum SignalError: Error {
    case invalidState(String)
    case internalError(String)
    case nullParameter(String)
    case invalidArgument(String)
    case invalidType(String)
    case invalidUtf8String(String)
    case protobufError(String)
    case legacyCiphertextVersion(String)
    case unknownCiphertextVersion(String)
    case unrecognizedMessageVersion(String)
    case invalidMessage(String)
    case invalidKey(String)
    case invalidSignature(String)
    case fingerprintVersionMismatch(String)
    case fingerprintParsingError(String)
    case sealedSenderSelfSend(String)
    case untrustedIdentity(String)
    case invalidKeyIdentifier(String)
    case sessionNotFound(String)
    case invalidSession(String)
    // case invalidRegistrationId(address: ProtocolAddress, message: String)
    case invalidSenderKeySession(distributionId: UUID, message: String)
    case duplicatedMessage(String)
    case verificationFailed(String)
    case cannotBeEmpty(String)
    case cannotStartWithDigit(String)
    case missingSeparator(String)
    case badDiscriminator(String)
    case badNicknameCharacter(String)
    case nicknameTooShort(String)
    case nicknameTooLong(String)
    case ioError(String)
    case invalidMediaInput(String)
    case unsupportedMediaInput(String)
    case callbackError(String)
    case unknown(UInt32, String)
}

internal typealias MsgFfiErrorRef = OpaquePointer

internal func checkError(_ error: MsgFfiErrorRef?) throws {
    guard let error = error else { return }

    let errType = signal_error_get_type(error)
    // If this actually throws we'd have an infinite loop before we hit the 'try!'.
    let errStr = try! invokeFnReturningString {
        signal_error_get_message(error, $0)
    }
    defer { signal_error_free(error) }

    switch MsgErrorCode(errType) {
    case MsgErrorCodeInvalidState:
        throw SignalError.invalidState(errStr)
    case MsgErrorCodeInternalError:
        throw SignalError.internalError(errStr)
    case MsgErrorCodeNullParameter:
        throw SignalError.nullParameter(errStr)
    case MsgErrorCodeInvalidArgument:
        throw SignalError.invalidArgument(errStr)
    case MsgErrorCodeInvalidType:
        throw SignalError.invalidType(errStr)
    case MsgErrorCodeInvalidUtf8String:
        throw SignalError.invalidUtf8String(errStr)
    case MsgErrorCodeProtobufError:
        throw SignalError.protobufError(errStr)
    case MsgErrorCodeLegacyCiphertextVersion:
        throw SignalError.legacyCiphertextVersion(errStr)
    case MsgErrorCodeUnknownCiphertextVersion:
        throw SignalError.unknownCiphertextVersion(errStr)
    case MsgErrorCodeUnrecognizedMessageVersion:
        throw SignalError.unrecognizedMessageVersion(errStr)
    case MsgErrorCodeInvalidMessage:
        throw SignalError.invalidMessage(errStr)
    case MsgErrorCodeFingerprintParsingError:
        throw SignalError.fingerprintParsingError(errStr)
    case MsgErrorCodeSealedSenderSelfSend:
        throw SignalError.sealedSenderSelfSend(errStr)
    case MsgErrorCodeInvalidKey:
        throw SignalError.invalidKey(errStr)
    case MsgErrorCodeInvalidSignature:
        throw SignalError.invalidSignature(errStr)
    case MsgErrorCodeFingerprintVersionMismatch:
        throw SignalError.fingerprintVersionMismatch(errStr)
    case MsgErrorCodeUntrustedIdentity:
        throw SignalError.untrustedIdentity(errStr)
    case MsgErrorCodeInvalidKeyIdentifier:
        throw SignalError.invalidKeyIdentifier(errStr)
    case MsgErrorCodeSessionNotFound:
        throw SignalError.sessionNotFound(errStr)
    case MsgErrorCodeInvalidSession:
        throw SignalError.invalidSession(errStr)
        // case MsgErrorCodeInvalidRegistrationId:
        // let address: ProtocolAddress = try invokeFnReturningNativeHandle {
        //     signal_error_get_address(error, $0)
        // }
        // throw SignalError.invalidRegistrationId(address: address, message: errStr)
        // case MsgErrorCodeInvalidSenderKeySession:
        // let distributionId = try invokeFnReturningUuid {
        //     signal_error_get_uuid(error, $0)
        // }
        // throw SignalError.invalidSenderKeySession(distributionId: distributionId, message: errStr)
    case MsgErrorCodeDuplicatedMessage:
        throw SignalError.duplicatedMessage(errStr)
    case MsgErrorCodeVerificationFailure:
        throw SignalError.verificationFailed(errStr)
    case MsgErrorCodeUsernameCannotBeEmpty:
        throw SignalError.cannotBeEmpty(errStr)
    case MsgErrorCodeUsernameCannotStartWithDigit:
        throw SignalError.cannotStartWithDigit(errStr)
    case MsgErrorCodeUsernameMissingSeparator:
        throw SignalError.missingSeparator(errStr)
    case MsgErrorCodeUsernameBadDiscriminator:
        throw SignalError.badDiscriminator(errStr)
    case MsgErrorCodeUsernameBadCharacter:
        throw SignalError.badNicknameCharacter(errStr)
    case MsgErrorCodeUsernameTooShort:
        throw SignalError.nicknameTooShort(errStr)
    case MsgErrorCodeUsernameTooLong:
        throw SignalError.nicknameTooLong(errStr)
    case MsgErrorCodeIoError:
        throw SignalError.ioError(errStr)
    case MsgErrorCodeInvalidMediaInput:
        throw SignalError.invalidMediaInput(errStr)
    case MsgErrorCodeUnsupportedMediaInput:
        throw SignalError.unsupportedMediaInput(errStr)
    case MsgErrorCodeCallbackError:
        throw SignalError.callbackError(errStr)
    default:
        throw SignalError.unknown(errType, errStr)
    }
}

internal func failOnError(_ error: MsgFfiErrorRef?) {
    failOnError { try checkError(error) }
}

internal func failOnError<Result>(_ fn: () throws -> Result) -> Result {
#if canImport(SignalCoreKit)
    do {
        return try fn()
    } catch {
        owsFail("unexpected error: \(error)")
    }
#else
    return try! fn()
#endif
}
