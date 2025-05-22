package org.cryptomator.jose.hpke;

import javax.crypto.KDF;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public record HKDF(KDF kdf) {

	public static HKDF sha256() {
		try {
			return new HKDF(KDF.getInstance("HKDF-SHA256"));
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("JVM doesn't support HKDF-SHA256", e);
		}
	}

	public static HKDF sha512() {
		try {
			return new HKDF(KDF.getInstance("HKDF-SHA512"));
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("JVM doesn't support HKDF-SHA512", e);
		}
	}

	public SecretKey deriveKey(HKDFParameterSpec params, String alg) {
		try {
			return kdf.deriveKey(alg, params);
		} catch (InvalidAlgorithmParameterException e) {
			throw new IllegalArgumentException("invalid KDF params", e);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("Invalid key alg", e);
		}
	}

	public byte[] deriveData(HKDFParameterSpec params) {
		try {
			return kdf.deriveData(params);
		} catch (InvalidAlgorithmParameterException e) {
			throw new IllegalArgumentException("invalid KDF params", e);
		}
	}

}
