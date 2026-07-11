package org.cryptomator.jose.alg;

import com.google.gson.JsonObject;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.hpke.HPKE;
import org.cryptomator.jose.util.ArrayUtil;

import javax.crypto.AEADBadTagException;
import javax.crypto.DecapsulateException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/// HPKE Key Encryption as defined in [draft-ietf-jose-hpke-encrypt, Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6):
/// HPKE seals the CEK, the encapsulated secret travels in the `ek` header parameter, and the content is encrypted with a regular [org.cryptomator.jose.Enc].
public final class HPKEKeyEncryptionAlg extends AbstractAlg {

	private static final byte[] SEPARATOR = {(byte) 0xFF};
	private static final byte[] RECIPIENT_STRUCTURE_LABEL = "JOSE-HPKE rcpt".getBytes(StandardCharsets.US_ASCII);
	private static final byte[] EMPTY = new byte[0];

	private final HPKE hpke;
	private final PublicKey publicKey;
	private final PrivateKey privateKey;

	public HPKEKeyEncryptionAlg(HPKE hpke, PublicKey publicKey, PrivateKey privateKey) {
		this.hpke = hpke;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	@Override
	public String name() {
		return hpke.baseName() + "-KE";
	}

	@Override
	public EncryptionResult encrypt(JsonObject combinedHeader, byte[] cek) {
		var sender = hpke.setupBaseS(publicKey, recipientStructure(combinedHeader));
		try (var ctx = sender.context()) {
			var perRecipientHeader = new JsonObject();
			perRecipientHeader.addProperty("alg", name());
			perRecipientHeader.addProperty("ek", Base64.getUrlEncoder().withoutPadding().encodeToString(sender.enc()));
			return new EncryptionResult(ctx.seal(EMPTY, cek), perRecipientHeader); // the HPKE aad parameter defaults to the empty octet sequence
		}
	}

	@Override
	protected byte[] decryptKey(JsonObject combinedHeader, byte[] encryptedKey) throws JoseDecryptException {
		if (!combinedHeader.has("ek")) {
			throw new JoseDecryptException("Missing ek header");
		}
		byte[] enc;
		try {
			enc = Base64.getUrlDecoder().decode(combinedHeader.get("ek").getAsString());
		} catch (IllegalArgumentException e) {
			throw new JoseDecryptException("Invalid base64 encoding", e);
		}
		try (var ctx = hpke.setupBaseR(enc, privateKey, recipientStructure(combinedHeader))) {
			return ctx.open(EMPTY, encryptedKey); // the HPKE aad parameter defaults to the empty octet sequence
		} catch (DecapsulateException e) {
			throw new DecryptKeyException("Failed to decapsulate 'ek'", e);
		} catch (AEADBadTagException e) {
			throw new DecryptKeyException("Failed to decrypt CEK", e);
		}
	}

	/// The `Recipient_structure` used as the HPKE `info` parameter, as defined in
	/// [draft-ietf-jose-hpke-encrypt, Section 6.1](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6.1):
	/// `ASCII("JOSE-HPKE rcpt") || 0xFF || ASCII(content_encryption_alg) || 0xFF || recipient_extra_info` (no additional application context, so the last field is empty)
	private static byte[] recipientStructure(JsonObject combinedHeader) {
		var contentEncryptionAlg = combinedHeader.get("enc").getAsString();
		return ArrayUtil.concat(RECIPIENT_STRUCTURE_LABEL, SEPARATOR, contentEncryptionAlg.getBytes(StandardCharsets.US_ASCII), SEPARATOR);
	}

}
