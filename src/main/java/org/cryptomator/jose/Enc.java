package org.cryptomator.jose;

import org.cryptomator.jose.enc.AESGCM;

/// Content Encryption Algorithms as specified by [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.1)
public sealed interface Enc permits AESGCM {

	// TODO A128CBC-HS256 and A256CBC-HS512 are required by spec

	Enc A256GCM = new AESGCM("A256GCM", 32);
	Enc A128GCM = new AESGCM("A128GCM", 16);

	/// Looks up the content encryption algorithm registered for the given `enc` header value.
	///
	/// @throws JoseDecryptException if the value does not identify a supported content encryption algorithm
	static Enc forName(String encValue) throws JoseDecryptException {
		return switch (encValue) {
			case "A256GCM" -> A256GCM;
			case "A128GCM" -> A128GCM;
			default -> throw new JoseDecryptException("Unsupported encryption algorithm: " + encValue);
		};
	}

	/// @return The `enc` header parameter value identifying this algorithm
	String encValue();

	/// @return A fresh random content encryption key of this algorithm's key size
	/// @apiNote Internal: called by the JWE builder. Users select an `Enc` and pass it to `JWE.build(...).encrypt(enc, alg...)`.
	byte[] generateCek();

	/// @return A fresh random IV of this algorithm's IV size
	/// @apiNote Internal: called by the JWE builder. Users select an `Enc` and pass it to `JWE.build(...).encrypt(enc, alg...)`.
	byte[] generateIv();

	/// @param cek The content encryption key
	/// @param iv The JWE Initialization Vector, which MUST be fresh for every encryption under the same key (see [#generateIv])
	/// @param aad The JWE Additional Authenticated Data encryption parameter
	/// @param plaintext The payload
	/// @return The ciphertext and the authentication tag
	/// @apiNote Internal: called by the JWE builder, which draws a fresh IV per encryption. Users select an `Enc` and pass it to `JWE.build(...).encrypt(enc, alg...)`;
	/// do not use this as a general-purpose AES-GCM helper, a repeated IV under one key breaks GCM's confidentiality and authentication.
	EncryptionResult encrypt(byte[] cek, byte[] iv, byte[] aad, byte[] plaintext);

	/// @param cek The content encryption key
	/// @param iv The JWE Initialization Vector
	/// @param aad The JWE Additional Authenticated Data encryption parameter
	/// @param ciphertext The JWE Ciphertext
	/// @param tag The JWE Authentication Tag
	/// @return The payload
	/// @throws JoseDecryptException if the CEK, IV or tag length does not match this algorithm, or authentication fails
	/// @apiNote Internal: called by the Key Encryption decrypt path. Users select an `Enc` and pass it to `JWE.build(...).encrypt(enc, alg...)`.
	byte[] decrypt(byte[] cek, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag) throws JoseDecryptException;

	/// @param ciphertext The JWE Ciphertext
	/// @param tag The JWE Authentication Tag
	record EncryptionResult(byte[] ciphertext, byte[] tag) {
	}

}
