/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 * <p>
 * Licensed according to the LICENSE file in this repository.
 */

package com.cystack.ready.libmessaging.protocol.ecc;

import com.cystack.ready.libmessaging.internal.Native;
import com.cystack.ready.libmessaging.internal.NativeHandleGuard;
import com.cystack.ready.libmessaging.protocol.InvalidKeyException;

public class ECPrivateKey implements NativeHandleGuard.Owner {
	private final long unsafeHandle;

	public static ECPrivateKey generate() {
		return new ECPrivateKey(Native.ECPrivateKey_Generate());
	}

	ECPrivateKey(byte[] privateKey) throws InvalidKeyException {
		this.unsafeHandle = Native.ECPrivateKey_Deserialize(privateKey);
	}

	public ECPrivateKey(long nativeHandle) {
		if (nativeHandle == 0) {
			throw new NullPointerException();
		}
		this.unsafeHandle = nativeHandle;
	}

	@Override
	@SuppressWarnings("deprecation")
	protected void finalize() {
		Native.ECPrivateKey_Destroy(this.unsafeHandle);
	}

	public byte[] serialize() {
		try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
			return Native.ECPrivateKey_Serialize(guard.nativeHandle());
		}
	}

	public byte[] calculateSignature(byte[] message) {
		try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
			return Native.ECPrivateKey_Sign(guard.nativeHandle(), message);
		}
	}

	public byte[] calculateAgreement(ECPublicKey other) {
		try (
				NativeHandleGuard privateKey = new NativeHandleGuard(this);
				NativeHandleGuard publicKey = new NativeHandleGuard(other);
		) {
			return Native.ECPrivateKey_Agree(privateKey.nativeHandle(), publicKey.nativeHandle());
		}
	}

	public long unsafeNativeHandleWithoutGuard() {
		return this.unsafeHandle;
	}

	public ECPublicKey publicKey() {
		try (NativeHandleGuard guard = new NativeHandleGuard(this)) {
			return new ECPublicKey(Native.ECPrivateKey_GetPublicKey(guard.nativeHandle()));
		}
	}
}
