package org.cryptomator.jose.alg;

import com.google.gson.JsonObject;
import org.cryptomator.jose.DecryptionAlg;
import org.cryptomator.jose.IntegratedEncryptionAlg;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.hpke.HPKE;

import javax.crypto.AEADBadTagException;
import javax.crypto.DecapsulateException;
import java.security.PrivateKey;
import java.security.PublicKey;

/// HPKE Integrated Encryption as defined in [draft-ietf-jose-hpke-encrypt, Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5):
/// HPKE encrypts the payload directly, the encapsulated secret travels in the JWE Encrypted Key field, and the JWE Protected Header
/// (as well as an optional JWE AAD) is bound to the ciphertext via the HPKE `aad` parameter.
public final class HPKEIntegratedAlg implements IntegratedEncryptionAlg, DecryptionAlg {

	private static final byte[] EMPTY = new byte[0];

	private final HPKE hpke;
	private final PublicKey publicKey;
	private final PrivateKey privateKey;

	public HPKEIntegratedAlg(HPKE hpke, PublicKey publicKey, PrivateKey privateKey) {
		this.hpke = hpke;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	@Override
	public String name() {
		return hpke.baseName();
	}

	@Override
	public Sealed seal(byte[] plaintext, byte[] aad) {
		var sender = hpke.setupBaseS(publicKey, EMPTY); // the HPKE info parameter defaults to the empty octet sequence
		try (var ctx = sender.context()) {
			return new Sealed(sender.enc(), ctx.seal(aad, plaintext));
		}
	}

	@Override
	public byte[] decrypt(JsonObject combinedHeader, JweParts parts) throws JoseDecryptException {
		if (combinedHeader.has("enc") || combinedHeader.has("ek")) {
			throw new JoseDecryptException("enc and ek headers must not be present for Integrated Encryption");
		}
		if (parts.iv().length > 0 || parts.tag().length > 0) {
			throw new JoseDecryptException("iv and tag must be empty for Integrated Encryption");
		}
		try (var ctx = hpke.setupBaseR(parts.encryptedKey(), privateKey, EMPTY)) {
			return ctx.open(parts.aad(), parts.ciphertext());
		} catch (DecapsulateException e) {
			throw new DecryptKeyException("Failed to decapsulate encrypted_key", e);
		} catch (AEADBadTagException e) {
			throw new DecryptKeyException("Failed to decrypt ciphertext", e); // key and content encryption are integrated, so a bad tag also means "wrong key"
		}
	}

}
