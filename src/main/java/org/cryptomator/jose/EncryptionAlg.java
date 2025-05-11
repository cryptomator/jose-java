package org.cryptomator.jose;

import com.google.gson.JsonObject;
import org.cryptomator.jose.alg.AbstractAlg;

public sealed interface EncryptionAlg extends Alg permits AbstractAlg {

	EncryptionResult encrypt(JsonObject combinedHeader, byte[] cek);

	record EncryptionResult(byte[] encryptedKey, JsonObject recipientSpecificHeader) {
	}

}
