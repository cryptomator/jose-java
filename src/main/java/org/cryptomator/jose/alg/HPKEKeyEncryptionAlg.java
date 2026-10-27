package org.cryptomator.jose.alg;

import com.google.gson.JsonObject;
import org.cryptomator.jose.HpkeKeyDecryptionAlg;
import org.cryptomator.jose.HpkeKeyEncryptionAlg;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.Psk;
import org.cryptomator.jose.hpke.HPKE;
import org.cryptomator.jose.util.ArrayUtil;
import org.cryptomator.jose.util.Base64Url;

import javax.crypto.AEADBadTagException;
import javax.crypto.DecapsulateException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;
import java.util.Set;

/// HPKE Key Encryption as defined in [draft-ietf-jose-hpke-encrypt, Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6):
/// HPKE seals the CEK, the encapsulated secret travels in the `ek` header parameter, and the content is encrypted with a regular [org.cryptomator.jose.Enc].
///
/// Runs in HPKE `mode_base`, or in `mode_psk` once a [Psk] is attached: the PSK identifier is then carried in the recipient's `psk_id` header parameter, and
/// the mode of a recipient (`psk_id` present or not) must match the configured PSK on decryption.
public final class HPKEKeyEncryptionAlg extends AbstractKeyAlg implements HpkeKeyEncryptionAlg, HpkeKeyDecryptionAlg {

	private static final byte[] SEPARATOR = {(byte) 0xFF};
	private static final byte[] RECIPIENT_STRUCTURE_LABEL = "JOSE-HPKE rcpt".getBytes(StandardCharsets.US_ASCII);
	private static final byte[] EMPTY = new byte[0];

	private final HPKE hpke;
	private final PublicKey publicKey;
	private final PrivateKey privateKey;
	private final Psk psk; // null for mode_base

	public HPKEKeyEncryptionAlg(HPKE hpke, PublicKey publicKey, PrivateKey privateKey) {
		this(hpke, publicKey, privateKey, null);
	}

	private HPKEKeyEncryptionAlg(HPKE hpke, PublicKey publicKey, PrivateKey privateKey, Psk psk) {
		this.hpke = hpke;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
		this.psk = psk;
	}

	@Override
	public String name() {
		return hpke.baseName() + "-KE";
	}

	@Override
	public HPKEKeyEncryptionAlg withPsk(Psk psk) {
		return new HPKEKeyEncryptionAlg(hpke, publicKey, privateKey, Objects.requireNonNull(psk, "psk"));
	}

	@Override
	public Set<String> generatedHeaderParams() {
		return psk == null ? Set.of("alg", "ek") : Set.of("alg", "ek", PskMode.PSK_ID);
	}

	@Override
	public EncryptionResult encrypt(JsonObject combinedHeader, byte[] cek) {
		var sender = hpke.setupS(publicKey, recipientStructure(combinedHeader), psk);
		try (var ctx = sender.context()) {
			var perRecipientHeader = new JsonObject();
			perRecipientHeader.addProperty("alg", name());
			perRecipientHeader.addProperty("ek", Base64Url.encode(sender.enc()));
			if (psk != null) {
				perRecipientHeader.addProperty(PskMode.PSK_ID, PskMode.headerValue(psk));
			}
			return new EncryptionResult(ctx.seal(EMPTY, cek), perRecipientHeader); // the HPKE aad parameter defaults to the empty octet sequence
		}
	}

	@Override
	protected byte[] decryptKey(JsonObject combinedHeader, byte[] encryptedKey) throws JoseDecryptException {
		var ekHeader = combinedHeader.get("ek");
		if (ekHeader == null || !ekHeader.isJsonPrimitive() || !ekHeader.getAsJsonPrimitive().isString()) {
			throw new JoseDecryptException("Missing or non-string ek header");
		}
		byte[] enc;
		try {
			enc = Base64Url.decode(ekHeader.getAsString());
		} catch (IllegalArgumentException e) {
			throw new JoseDecryptException("Invalid base64 encoding", e);
		}
		PskMode.verify(combinedHeader, psk);
		try (var ctx = hpke.setupR(enc, privateKey, recipientStructure(combinedHeader), psk)) {
			return ctx.open(EMPTY, encryptedKey); // the HPKE aad parameter defaults to the empty octet sequence
		} catch (DecapsulateException e) {
			throw new DecryptKeyException("Failed to decapsulate 'ek'", e);
		} catch (AEADBadTagException e) {
			throw new DecryptKeyException("Failed to decrypt CEK", e); // wrong private key, or wrong PSK in mode_psk
		}
	}

	/// The `Recipient_structure` used as the HPKE `info` parameter, as defined in
	/// [draft-ietf-jose-hpke-encrypt, Section 6.1](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6.1):
	/// `ASCII("JOSE-HPKE rcpt") || 0xFF || ASCII(content_encryption_alg) || 0xFF || recipient_extra_info` (no additional application context, so the last field is empty)
	private static byte[] recipientStructure(JsonObject combinedHeader) {
		var encHeader = combinedHeader.get("enc"); // guaranteed present upstream (builder on encrypt, AbstractKeyAlg on decrypt); guard against direct misuse
		if (encHeader == null || !encHeader.isJsonPrimitive() || !encHeader.getAsJsonPrimitive().isString()) {
			throw new IllegalStateException("HPKE Key Encryption requires a string 'enc' header");
		}
		return ArrayUtil.concat(RECIPIENT_STRUCTURE_LABEL, SEPARATOR, encHeader.getAsString().getBytes(StandardCharsets.US_ASCII), SEPARATOR);
	}

}
