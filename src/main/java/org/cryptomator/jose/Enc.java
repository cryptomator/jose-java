package org.cryptomator.jose;

import org.cryptomator.jose.enc.AESGCM;

/// Content Encryption Algorithms as specified by [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.1)
public sealed interface Enc permits AESGCM {

	// TODO A128CBC-HS256 and A256CBC-HS512 are required by spec

	Enc A256GCM = new AESGCM("A256GCM", 32);
	Enc A128GCM = new AESGCM("A128GCM", 16);

	/// Looks up the content encryption algorithm registered for the given `enc` header value.
	static Enc forName(String encValue) {
		return switch (encValue) {
			case "A256GCM" -> A256GCM;
			case "A128GCM" -> A128GCM;
			default -> throw new UnsupportedOperationException("Unsupported encryption algorithm: " + encValue);
		};
	}

	String encValue();

	byte[] generateCek();

	byte[] generateIv();

	EncryptionResult encrypt(byte[] cek, byte[] iv, byte[] aad, byte[] plaintext);

	byte[] decrypt(byte[] cek, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag) throws JoseDecryptException;

	record EncryptionResult(byte[] ciphertext, byte[] tag) {
	}

}
