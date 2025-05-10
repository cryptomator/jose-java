package org.cryptomator.jose;


import com.google.gson.JsonObject;
import org.cryptomator.jose.alg.AbstractAlg;

public sealed interface DecryptionAlg extends Alg permits AbstractAlg {

	/// @param combinedHeader The combined header (i.e. protected, shared unprotected and per-recipient unprotected)
	/// @param encryptedKey The encrypted key
	byte[] decrypt(JsonObject combinedHeader, byte[] encryptedKey) throws JoseDecryptException;
}
