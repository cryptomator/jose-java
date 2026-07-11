package org.cryptomator.jose.alg;

import com.google.gson.JsonObject;
import org.cryptomator.jose.DecryptionAlg;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.EncryptionAlg;
import org.cryptomator.jose.JoseDecryptException;

import java.util.Arrays;

public sealed abstract class AbstractAlg implements DecryptionAlg, EncryptionAlg permits EcdhEsAlg, Pbes2Alg, HPKEKeyEncryptionAlg {

	@Override
	public final byte[] decrypt(JsonObject combinedHeader, JweParts parts) throws JoseDecryptException {
		if (!combinedHeader.has("enc")) {
			throw new JoseDecryptException("Missing enc header");
		}
		var enc = Enc.forName(combinedHeader.get("enc").getAsString());
		var cek = decryptKey(combinedHeader, parts.encryptedKey());
		try {
			return enc.decrypt(cek, parts.iv(), parts.aad(), parts.ciphertext(), parts.tag());
		} finally {
			Arrays.fill(cek, (byte) 0x00);
		}
	}

	/// Decrypts the recipient's JWE Encrypted Key, returning the CEK.
	///
	/// @param combinedHeader The combined header (i.e. protected, shared unprotected and per-recipient unprotected)
	/// @param encryptedKey The encrypted key
	protected abstract byte[] decryptKey(JsonObject combinedHeader, byte[] encryptedKey) throws JoseDecryptException;

}
