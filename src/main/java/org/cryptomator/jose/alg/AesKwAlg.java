package org.cryptomator.jose.alg;

import com.google.gson.JsonObject;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.KeyWrapAlg;

import javax.crypto.SecretKey;
import java.util.Arrays;

/// Key Encryption with AES Key Wrap using a caller-supplied 256-bit key encryption key (`A256KW`), as defined in
/// [RFC 7518, Section 4.4](https://www.rfc-editor.org/rfc/rfc7518#section-4.4).
public final class AesKwAlg extends AbstractKeyAlg implements KeyWrapAlg {

	private static final String ALG_NAME = "A256KW";
	private static final int KEY_LENGTH = 32;

	private final SecretKey kek;

	/// @param kek The key encryption key: a 256-bit AES key, which remains owned (and eventually destroyed) by the caller
	/// @throws IllegalArgumentException if the key is not a 256-bit AES key
	public AesKwAlg(SecretKey kek) {
		if (!"AES".equalsIgnoreCase(kek.getAlgorithm())) {
			throw new IllegalArgumentException("Key encryption key must be an AES key, but was: " + kek.getAlgorithm());
		}
		var encoded = kek.getEncoded();
		if (encoded == null) {
			throw new IllegalArgumentException("Key encryption key must be extractable"); // e.g. hardware-backed keys are not supported
		}
		try {
			if (encoded.length != KEY_LENGTH) {
				throw new IllegalArgumentException("Key encryption key must be " + KEY_LENGTH * Byte.SIZE + " bits long, but was " + encoded.length * Byte.SIZE);
			}
		} finally {
			Arrays.fill(encoded, (byte) 0x00);
		}
		this.kek = kek;
	}

	@Override
	public String name() {
		return ALG_NAME;
	}

	@Override
	public EncryptionResult encrypt(JsonObject combinedHeader, byte[] cek) {
		var perRecipientHeader = new JsonObject();
		perRecipientHeader.addProperty("alg", ALG_NAME);
		return new EncryptionResult(AesKw.wrap(kek, cek), perRecipientHeader);
	}

	@Override
	protected byte[] decryptKey(JsonObject combinedHeader, byte[] encryptedKey) throws JoseDecryptException {
		var algHeader = combinedHeader.get("alg");
		if (algHeader == null || !algHeader.isJsonPrimitive() || !ALG_NAME.equals(algHeader.getAsString())) {
			throw new DecryptKeyException("alg is not " + ALG_NAME);
		}
		return AesKw.unwrap(kek, encryptedKey);
	}

}
