package org.cryptomator.jose.alg;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/// AES Key Wrap ([RFC 3394](https://www.rfc-editor.org/rfc/rfc3394)) as used by the `A128KW`/`A256KW` family and the `+A256KW` suffixed algorithms
/// ([RFC 7518, Section 4.4](https://www.rfc-editor.org/rfc/rfc7518#section-4.4)). The caller owns the KEK; this helper never destroys it.
final class AesKw {

	private static final String JCA_ALG = "AESWrap";
	private static final int BLOCK_SIZE = 8; // RFC 3394 operates on 64-bit blocks; the wrapped key is one block longer than the key data

	private AesKw() {
	}

	/// Wraps the given key data with the given key encryption key.
	///
	/// @param kek The AES key encryption key
	/// @param keyData The key to wrap (e.g. the CEK), a multiple of 8 bytes and at least 16 bytes long
	/// @return The wrapped key (8 bytes longer than `keyData`)
	/// @throws IllegalStateException if the KEK is unsuitable or the key data has an invalid length (both indicate a programming error, not a malformed input)
	static byte[] wrap(SecretKey kek, byte[] keyData) {
		try {
			var cipher = Cipher.getInstance(JCA_ALG);
			cipher.init(Cipher.WRAP_MODE, kek);
			return cipher.wrap(new SecretKeySpec(keyData, "AES"));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new UnsupportedOperationException("JVM does not support " + JCA_ALG, e);
		} catch (InvalidKeyException e) {
			throw new IllegalStateException("Unsuitable key encryption key", e);
		} catch (IllegalBlockSizeException e) {
			throw new IllegalStateException("Key data must be a multiple of " + BLOCK_SIZE + " bytes", e);
		}
	}

	/// Unwraps the given wrapped key with the given key encryption key, verifying its integrity.
	///
	/// @param kek The AES key encryption key
	/// @param wrappedKey The wrapped key
	/// @return The unwrapped key data
	/// @throws DecryptKeyException if the wrapped key is malformed or its integrity check fails (i.e. the KEK does not match)
	static byte[] unwrap(SecretKey kek, byte[] wrappedKey) throws DecryptKeyException {
		if (wrappedKey.length < 3 * BLOCK_SIZE || wrappedKey.length % BLOCK_SIZE != 0) {
			throw new DecryptKeyException("Invalid wrapped key length: " + wrappedKey.length);
		}
		try {
			var cipher = Cipher.getInstance(JCA_ALG);
			cipher.init(Cipher.UNWRAP_MODE, kek);
			return cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY).getEncoded();
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new UnsupportedOperationException("JVM does not support " + JCA_ALG, e);
		} catch (InvalidKeyException e) {
			throw new DecryptKeyException("Key unwrapping failed with the given key encryption key", e);
		}
	}

}
