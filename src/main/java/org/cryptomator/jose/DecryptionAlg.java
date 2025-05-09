package org.cryptomator.jose;


import com.google.gson.JsonObject;
import org.cryptomator.jose.alg.AbstractAlg;

public sealed interface DecryptionAlg extends Alg permits AbstractAlg {

	byte[] decrypt(JsonObject combinedHeader, byte[] encryptedKey) throws JoseDecryptException;
}
