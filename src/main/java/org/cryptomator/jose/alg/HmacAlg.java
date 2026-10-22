package org.cryptomator.jose.alg;

import org.cryptomator.jose.MacAlg;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/// HMAC with SHA-2 for JWS (`HS256`, `HS384`, `HS512`), see [RFC 7518, Section 3.2](https://www.rfc-editor.org/rfc/rfc7518#section-3.2).
public final class HmacAlg implements MacAlg {

	public enum Type {
		HS256("HS256", "HmacSHA256", 32),
		HS384("HS384", "HmacSHA384", 48),
		HS512("HS512", "HmacSHA512", 64),
		;

		private final String jwaAlgName;
		private final String jcaAlgName;
		private final int minKeyLength; // RFC 7518 §3.2: a key of the same size as the hash output or larger MUST be used

		Type(String jwaAlgName, String jcaAlgName, int minKeyLength) {
			this.jwaAlgName = jwaAlgName;
			this.jcaAlgName = jcaAlgName;
			this.minKeyLength = minKeyLength;
		}
	}

	private final Type type;
	private final SecretKey key;

	/// @param type The HMAC variant
	/// @param key The HMAC key, which remains owned (and eventually destroyed) by the caller
	/// @throws IllegalArgumentException if the key is shorter than the hash output
	public HmacAlg(Type type, SecretKey key) {
		var encoded = key.getEncoded();
		if (encoded == null) {
			throw new IllegalArgumentException("Key must be extractable"); // e.g. hardware-backed keys are not supported
		}
		try {
			if (encoded.length < type.minKeyLength) {
				throw new IllegalArgumentException(type.jwaAlgName + " requires a key of at least " + type.minKeyLength * Byte.SIZE + " bits, but got " + encoded.length * Byte.SIZE);
			}
		} finally {
			Arrays.fill(encoded, (byte) 0x00);
		}
		this.type = type;
		this.key = key;
	}

	@Override
	public String name() {
		return type.jwaAlgName;
	}

	@Override
	public byte[] sign(byte[] signingInput) {
		try {
			var mac = Mac.getInstance(type.jcaAlgName);
			mac.init(key);
			return mac.doFinal(signingInput);
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("JVM does not support " + type.jcaAlgName, e);
		} catch (InvalidKeyException e) {
			throw new IllegalStateException("Unsuitable key for " + type.jcaAlgName, e);
		}
	}

}
