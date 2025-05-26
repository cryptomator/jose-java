package org.cryptomator.jose.util;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class CryptoHelper {

	public static final SecureRandom CSPRNG;

	static {
		try {
			CSPRNG = SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {
			// "Every implementation of the Java platform is required to support at least one strong SecureRandom implementation."
			throw new AssertionError("No strong SecureRandom implementation available", e);
		}
	}

	private CryptoHelper() {
		// prevent instantiation
	}

	public static byte[] randomBytes(int length) {
		byte[] bytes = new byte[length];
		CSPRNG.nextBytes(bytes);
		return bytes;
	}

	public static SecretKey secretKey(byte[] cek, String jcaAlgorithmName) {
		return new SecretKeySpec(cek, jcaAlgorithmName);
	}
}
