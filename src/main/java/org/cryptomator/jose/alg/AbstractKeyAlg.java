package org.cryptomator.jose.alg;

import com.google.gson.JsonObject;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.KeyDecryptionAlg;
import org.cryptomator.jose.KeyEncryptionAlg;

import java.util.Arrays;

/// Abstract base for algorithms of the Key Encryption Key Management Mode: HPKE/PBES2/ECDH-ES protect (wrap) the content encryption key (CEK),
/// which a separate [Enc] then uses to protect the payload. Subclasses only implement [#decryptKey] (and [KeyEncryptionAlg#encrypt]);
/// this class composes the shared decrypt flow (resolve `enc`, unwrap the CEK, decrypt the content, then wipe the CEK).
public abstract sealed class AbstractKeyAlg implements KeyEncryptionAlg, KeyDecryptionAlg permits EcdhEsAlg, Pbes2Alg, HPKEKeyEncryptionAlg {

	@Override
	public final byte[] decrypt(JsonObject combinedHeader, JweParts parts) throws JoseDecryptException {
		var encHeader = combinedHeader.get("enc");
		if (encHeader == null || !encHeader.isJsonPrimitive() || !encHeader.getAsJsonPrimitive().isString()) {
			throw new JoseDecryptException("Missing or non-string enc header");
		}
		var enc = Enc.forName(encHeader.getAsString());
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
