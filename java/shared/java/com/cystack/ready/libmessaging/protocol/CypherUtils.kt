//
// Copyright 2023 Ready.io
//

import com.cystack.ready.libmessaging.internal.Native

fun signalEncryptData(key: ByteArray, data: ByteArray, iv: ByteArray): ByteArray {
	return Native.Aes256Cbc_Encrypt(data, key, iv)
}

fun signalDecryptData(key: ByteArray, data: ByteArray, iv: ByteArray): ByteArray {
	return Native.Aes256Cbc_Decrypt(data, key, iv)
}
