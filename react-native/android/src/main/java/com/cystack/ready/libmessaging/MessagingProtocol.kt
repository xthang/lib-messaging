package com.cystack.ready.libmessaging

import android.util.Log
import com.cystack.ready.libmessaging.protocol.ecc.Curve
import com.cystack.ready.libmessaging.protocol.ecc.ECPrivateKey
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableArray
import signalDecryptData
import signalEncryptData

class MessagingProtocol(reactApplicationContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactApplicationContext) {
	private val TAG = "MessagingProtocol"

	override fun getName() = this::class.simpleName!!

//	override fun getConstants(): MutableMap<String, Any> =
//		hashMapOf("some key" to "some value")

	@ReactMethod
	fun createKeyPair(rawPrivateKey: ReadableArray?, promise: Promise) {
		try {
			val privateKey = if (rawPrivateKey != null) {
				Curve.decodePrivatePoint(rawPrivateKey.toByteArray())
			} else {
				ECPrivateKey.generate()
			}
			val publicKey = privateKey.publicKey()
			promise.resolve(
				Arguments.fromList(
					listOf(privateKey.serialize().asList(), publicKey.serialize().asList())
				)
			)
		} catch (error: Throwable) {
			Log.e(TAG, "createKeyPair ERROR:", error)
			promise.reject("createKeyPair_failure", null, error)
		}
	}

	@ReactMethod
	fun privateKeySign(
		rawPrivateKey: ReadableArray, data: ReadableArray,
		promise: Promise,
	) {
		try {
			val privateKey = Curve.decodePrivatePoint(rawPrivateKey.toByteArray())
			promise.resolve(privateKey.calculateSignature(data.toByteArray()).toReadableArray())
		} catch (error: Throwable) {
			Log.e(TAG, "privateKeySign ERROR:", error)
			promise.reject("privateKeySign_failure", null, error)
		}
	}

	@ReactMethod
	fun verifySignature(
		rawPublicKey: ReadableArray, data: ReadableArray, signature: ReadableArray,
		promise: Promise,
	) {
		try {
			val publicKey = Curve.decodePoint(rawPublicKey.toByteArray(), 0)
			promise.resolve(publicKey.verifySignature(data.toByteArray(), signature.toByteArray()))
		} catch (error: Throwable) {
			Log.e(TAG, "verifySignature ERROR:", error)
			promise.reject("verifySignature_failure", null, error)
		}
	}

	@ReactMethod
	fun privateKeyAgreeWithOtherPublicKey(
		rawPrivateKey: ReadableArray, rawPublicKey: ReadableArray,
		promise: Promise,
	) {
		try {
			val privateKey = Curve.decodePrivatePoint(rawPrivateKey.toByteArray())
			val publicKey = Curve.decodePoint(rawPublicKey.toByteArray(), 0)
			promise.resolve(privateKey.calculateAgreement(publicKey).toReadableArray())
		} catch (error: Throwable) {
			Log.e(TAG, "privateKeyAgreeWithOtherPublicKey ERROR:", error)
			promise.reject("privateKeyAgreementWithOtherPublicKey_failure", null, error)
		}
	}

	@ReactMethod
	fun HKDF(
		inputKeyMaterial: ReadableArray, salt: ReadableArray?, info: ReadableArray,
		promise: Promise,
	) {
		// owsAssertDebug(!Thread.isMainThread)

		try {
			val hkdf = com.cystack.ready.libmessaging.protocol.kdf.HKDF.deriveSecrets(
				inputKeyMaterial.toByteArray(),
				salt?.toByteArray(),
				info.toByteArray(),
				80
			)

			promise.resolve(
				Arguments.fromList(
					listOf(
						hkdf.slice(0..31),
						hkdf.slice(32..63),
						hkdf.slice(64..79)
					)
				)
			)
		} catch (error: Throwable) {
			Log.e(TAG, "HKDF ERROR:", error)
			promise.reject("HKDF_failure", null, error)
		}
	}

	@ReactMethod
	fun computeMac(
		macKey: ReadableArray, data: ReadableArray,
		promise: Promise,
	) {
		// owsAssertDebug(!Thread.isMainThread)

		try {
			// val mac = IncrementalMacContext(key: macKey, chunkSize: .bytes(chunkSize <= 0 ? 32 : chunkSize))
			// mac.update(data)
			// promise.resolve(mac.finalize())

			promise.resolve(
				com.cystack.ready.libmessaging.protocol.incrementalmac.computeMac(
					macKey.toByteArray(),
					data.toByteArray()
				).toReadableArray()
			)
		} catch (error: Throwable) {
			Log.e(TAG, "computeMac ERROR:", error)
			promise.reject("computeMac_failure", null, error)
		}
	}

	@ReactMethod
	fun verifyMac(
		data: ReadableArray, macKey: ReadableArray, mac: ReadableArray, length: Int,
		promise: Promise,
	) {
		// owsAssertDebug(!Thread.isMainThread)

		try {
			promise.resolve(
				com.cystack.ready.libmessaging.protocol.incrementalmac.verifyMac(
					data.toByteArray(),
					macKey.toByteArray(),
					mac.toByteArray(),
					length
				)
			)
		} catch (error: Throwable) {
			Log.e(TAG, "verifyMac ERROR:", error)
			promise.reject("verifyMac_failure", null, error)
		}
	}

	@ReactMethod
	fun encrypt(
		key: ReadableArray, data: ReadableArray, iv: ReadableArray,
		promise: Promise,
	) {
		// owsAssertDebug(!Thread.isMainThread)

		try {
			promise.resolve(signalEncryptData(key.toByteArray(), data.toByteArray(), iv.toByteArray()).toReadableArray())
		} catch (error: Throwable) {
			Log.e(TAG, "encrypt ERROR:", error)
			promise.reject("encrypt_failure", null, error)
		}
	}

	@ReactMethod
	fun decrypt(
		key: ReadableArray, data: ReadableArray, iv: ReadableArray,
		promise: Promise,
	) {
		// owsAssertDebug(!Thread.isMainThread)

		try {
			promise.resolve(signalDecryptData(key.toByteArray(), data.toByteArray(), iv.toByteArray()).toReadableArray())
		} catch (error: Throwable) {
			Log.e(TAG, "decrypt ERROR:", error)
			promise.reject("decrypt_failure", null, error)
		}
	}
}

fun ReadableArray.toByteArray(): ByteArray = this.toArrayList().map { (it as Double).toUInt().toByte() }.toByteArray()

fun ByteArray.toReadableArray(): ReadableArray = Arguments.fromList(this.map { it.toUByte().toDouble() })
