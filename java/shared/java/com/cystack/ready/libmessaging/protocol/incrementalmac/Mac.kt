package com.cystack.ready.libmessaging.protocol.incrementalmac

import com.cystack.ready.libmessaging.internal.Native

fun computeMac(data: ByteArray, macKey: ByteArray): ByteArray {
	return Native.Mac_Compute(macKey, data)
}

fun verifyMac(data: ByteArray, macKey: ByteArray, theirMac: ByteArray, length: Int): Boolean {
	return Native.Mac_Verify(macKey, data, theirMac, length)
}