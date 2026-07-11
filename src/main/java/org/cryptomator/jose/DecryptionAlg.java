package org.cryptomator.jose;


import com.google.gson.JsonObject;

public sealed interface DecryptionAlg extends Alg permits KeyDecryptionAlg, IntegratedDecryptionAlg {

	/// Decrypts one recipient's view of the JWE, returning the payload.
	///
	/// @param combinedHeader The combined header (i.e. protected, shared unprotected and per-recipient unprotected)
	/// @param parts The raw JWE parts
	byte[] decrypt(JsonObject combinedHeader, JweParts parts) throws JoseDecryptException;

	/// The raw (base64url-decoded) parts of a JWE relevant for decrypting one recipient.
	///
	/// @param encryptedKey The recipient's JWE Encrypted Key (Key Encryption: the encrypted CEK; Integrated Encryption: the HPKE encapsulated secret)
	/// @param iv JWE Initialization Vector (empty for Integrated Encryption)
	/// @param ciphertext JWE Ciphertext
	/// @param tag JWE Authentication Tag (empty for Integrated Encryption)
	/// @param aad The JWE Additional Authenticated Data encryption parameter, i.e. `ASCII(BASE64URL(protected) [ '.' BASE64URL(aad) ])`
	record JweParts(byte[] encryptedKey, byte[] iv, byte[] ciphertext, byte[] tag, byte[] aad) {
	}

}
