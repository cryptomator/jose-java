package org.cryptomator.jose.alg;

import org.jspecify.annotations.Nullable;
import com.google.gson.JsonObject;
import org.cryptomator.jose.IntegratedDecryptionAlg;
import org.cryptomator.jose.IntegratedEncryptionAlg;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.Psk;
import org.cryptomator.jose.hpke.HPKE;

import javax.crypto.AEADBadTagException;
import javax.crypto.DecapsulateException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/// HPKE Integrated Encryption as defined in [draft-ietf-jose-hpke-encrypt, Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5):
/// HPKE encrypts the payload directly, the encapsulated secret travels in the JWE Encrypted Key field, and the JWE Protected Header
/// (as well as an optional JWE AAD) is bound to the ciphertext via the HPKE `aad` parameter.
///
/// Runs in HPKE `mode_base`, or in `mode_psk` once a [Psk] is attached: the PSK identifier is then carried in the `psk_id` protected header parameter, and
/// the mode of a token (`psk_id` present or not) must match the configured PSK on decryption.
public final class HPKEIntegratedAlg implements IntegratedEncryptionAlg, IntegratedDecryptionAlg {

	private static final byte[] EMPTY = new byte[0];

	private final HPKE hpke;
	private final @Nullable PublicKey publicKey; // the encrypt side
	private final @Nullable PrivateKey privateKey; // the decrypt side
	private final @Nullable Psk psk; // null for mode_base

	public HPKEIntegratedAlg(HPKE hpke, @Nullable PublicKey publicKey, @Nullable PrivateKey privateKey) {
		this(hpke, publicKey, privateKey, null);
	}

	private HPKEIntegratedAlg(HPKE hpke, @Nullable PublicKey publicKey, @Nullable PrivateKey privateKey, @Nullable Psk psk) {
		this.hpke = hpke;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
		this.psk = psk;
	}

	@Override
	public String name() {
		return hpke.baseName();
	}

	@Override
	public HPKEIntegratedAlg withPsk(Psk psk) {
		return new HPKEIntegratedAlg(hpke, publicKey, privateKey, Objects.requireNonNull(psk, "psk"));
	}

	@Override
	public JsonObject generatedProtectedHeader() {
		var header = new JsonObject();
		header.addProperty("alg", name());
		if (psk != null) {
			header.addProperty(PskMode.PSK_ID, PskMode.headerValue(psk)); // draft Section 5: psk_id is a protected header parameter
		}
		return header;
	}

	@Override
	public Sealed seal(byte[] plaintext, byte[] aad) {
		var sender = hpke.setupS(publicKey, EMPTY, psk); // the HPKE info parameter defaults to the empty octet sequence
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
		PskMode.verify(combinedHeader, psk);
		try (var ctx = hpke.setupR(parts.encryptedKey(), privateKey, EMPTY, psk)) {
			return ctx.open(parts.aad(), parts.ciphertext());
		} catch (DecapsulateException | AEADBadTagException e) {
			// Integrated Encryption has no separate key step, so a decapsulation or authentication failure just means this recipient/key (or PSK) does not match.
			throw new JoseDecryptException("Failed to open Integrated Encryption ciphertext", e);
		}
	}

}
