package org.cryptomator.jose;

import com.google.gson.JsonObject;
import org.cryptomator.jose.alg.AbstractAlg;

/// Key Encryption: the alg encrypts the content encryption key (CEK); the payload is encrypted by a separate [Enc].
public sealed interface KeyEncryptionAlg extends EncryptionAlg permits AbstractAlg {

	/// @param combinedHeader The combined header (i.e. protected and shared unprotected), already containing the `enc` header parameter
	/// @param cek The content encryption key to encrypt
	EncryptionResult encrypt(JsonObject combinedHeader, byte[] cek);

	record EncryptionResult(byte[] encryptedKey, JsonObject recipientSpecificHeader) {
	}

}
