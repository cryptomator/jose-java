package org.cryptomator.jose.jwe;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.cryptomator.jose.DecryptionAlg;
import org.cryptomator.jose.enc.DecryptCiphertextException;
import org.cryptomator.jose.IntegratedDecryptionAlg;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.JoseParseException;
import org.cryptomator.jose.util.Ascii;
import org.cryptomator.jose.util.Base64Url;
import org.cryptomator.jose.util.JsonHelper;
import org.cryptomator.jose.util.Utf8;

import java.util.List;
import java.util.Optional;

/// A parsed, not yet decrypted JWE in any of the three serializations, normalized to the General JSON Serialization's structure.
/// Instances produced by [JWEParser] have passed the JOSE Header checks (incl. `crit`); instances constructed directly have not.
///
/// @param protectedHeader   BASE64URL(UTF8(JWE Protected Header))
/// @param unprotectedHeader JWE Shared Unprotected Header
/// @param recipients        JWE Per-Recipient Unprotected Header and encrypted keys
/// @param iv                BASE64URL(JWE Initialization Vector)
/// @param ciphertext        BASE64URL(JWE Ciphertext)
/// @param tag               BASE64URL(JWE Authentication Tag)
/// @param aad               BASE64URL(JWE AAD)
public record ParsedJWE(String protectedHeader, JsonObject unprotectedHeader, JsonArray recipients, String iv,
						String ciphertext, String tag, String aad) {

	/// The decoded JWE Protected Header. Like every header accessor on this class it is NOT authenticated until [#decrypt] succeeds, so use it to pick keys, not to make trust decisions.
	///
	/// @return The protected header, empty if absent
	public JsonObject parsedProtectedHeader() {
		if (protectedHeader.isEmpty()) {
			return new JsonObject();
		}
		try {
			return JsonHelper.parseObject(Utf8.strictString(Base64Url.decode(protectedHeader)));
		} catch (JoseParseException e) {
			throw new IllegalArgumentException("Malformed protected header", e); // cannot happen for instances produced by JWEParser
		}
	}

	/// The per-recipient unprotected headers of all recipients, in order, before any decryption attempt (e.g. to pick a key by `kid`).
	///
	/// @return One (possibly empty) header object per recipient
	public List<JsonObject> recipientHeaders() {
		return recipients.asList().stream()
				.map(r -> r.getAsJsonObject().has("header") ? r.getAsJsonObject().getAsJsonObject("header").deepCopy() : new JsonObject())
				.toList();
	}

	/// Decrypts the JWE, attempting each recipient against each of the provided algorithms (matched by `alg`) in order.
	///
	/// @param algs The candidate decryption algorithms
	/// @return The decrypted JWE
	/// @throws JoseDecryptException if no recipient could be decrypted with the provided algorithms
	public DecryptedJWE decrypt(DecryptionAlg... algs) throws JoseDecryptException {
		return decrypt(Optional.empty(), algs);
	}

	/// Decrypts the JWE for the recipient identified by the given `kid`.
	///
	/// @param kid The `kid` header parameter value identifying the recipient
	/// @param alg The decryption algorithm for that recipient
	/// @return The decrypted JWE
	/// @throws JoseDecryptException if no or several recipients carry the `kid`, or if that recipient could not be decrypted
	public DecryptedJWE decrypt(String kid, DecryptionAlg alg) throws JoseDecryptException {
		return decrypt(Optional.of(kid), alg);
	}

	private DecryptedJWE decrypt(Optional<String> kid, DecryptionAlg... algs) throws JoseDecryptException {
		var parsedProtectedHeader = parsedProtectedHeader();
		var sharedHeader = JsonHelper.disjointUnion(parsedProtectedHeader, unprotectedHeader);

		var combinedAad = protectedHeader + (aad.isEmpty() ? "" : "." + aad);
		final byte[] combinedAadBytes;
		try {
			combinedAadBytes = Ascii.strictBytes(combinedAad); // the protected header and aad are base64url per RFC 7516, hence ASCII; reject anything else rather than silently substituting '?'
		} catch (IllegalArgumentException e) {
			throw new JoseDecryptException("Malformed JWE: protected header and aad must be US-ASCII", e);
		}
		final byte[] decodedIv, decodedCiphertext, decodedTag;
		try {
			decodedIv = Base64Url.decode(iv);
			decodedCiphertext = Base64Url.decode(ciphertext);
			decodedTag = Base64Url.decode(tag);
		} catch (IllegalArgumentException e) {
			throw new JoseDecryptException("Malformed JWE: iv, ciphertext and tag must be base64url", e); // shared by all recipients, so not worth retrying
		}

		var candidates = kid.isPresent() ? recipientsWithKid(kid.get(), sharedHeader) : recipients.asList();
		var failure = new JoseDecryptException(kid.isPresent() ? "Recipient '" + kid.get() + "' could not be decrypted." : "No matching recipient found for decryption.");
		for (var recipient : candidates) {
			var recipientJson = recipient.getAsJsonObject();
			final byte[] encryptedKey;
			try {
				encryptedKey = Base64Url.decode(recipientJson.get("encrypted_key").getAsString());
			} catch (IllegalArgumentException e) {
				failure.addSuppressed(new JoseDecryptException("Malformed encrypted_key: not base64url", e));
				continue;
			}
			var perRecipientUnprotectedHeader = recipientJson.has("header")
					? recipientJson.get("header").getAsJsonObject()
					: new JsonObject();
			var combinedHeader = JsonHelper.disjointUnion(perRecipientUnprotectedHeader, sharedHeader);
			var algHeader = combinedHeader.get("alg");
			if (algHeader == null || !algHeader.isJsonPrimitive() || !algHeader.getAsJsonPrimitive().isString()) {
				failure.addSuppressed(new JoseDecryptException("Missing or non-string alg header"));
				continue;
			}
			var algValue = algHeader.getAsString();
			var parts = new DecryptionAlg.JweParts(encryptedKey, decodedIv, decodedCiphertext, decodedTag, combinedAadBytes);
			for (var alg : algs) {
				if (!algValue.equals(alg.name())) {
					continue;
				}
				if (alg instanceof IntegratedDecryptionAlg && !parsedProtectedHeader.has("alg")) {
					// draft-ietf-jose-hpke-encrypt §5: for Integrated Encryption the protected header MUST contain alg (it is part of the HPKE aad)
					failure.addSuppressed(new JoseDecryptException("alg must be in the protected header for Integrated Encryption"));
					continue;
				}
				if (alg instanceof IntegratedDecryptionAlg && recipients.size() != 1) {
					// draft-ietf-jose-hpke-encrypt §5: Integrated Encryption has exactly one recipient (HPKE encrypts the payload directly, there is no shared CEK)
					failure.addSuppressed(new JoseDecryptException("Integrated Encryption requires exactly one recipient"));
					continue;
				}
				try {
					var payload = alg.decrypt(combinedHeader, parts);
					return new DecryptedJWE(payloadString(payload), parsedProtectedHeader, JsonHelper.union(unprotectedHeader, perRecipientUnprotectedHeader), aad);
				} catch (DecryptCiphertextException e) {
					throw e; // the key matched but the content is corrupt; other recipients share the same ciphertext and would fail identically
				} catch (JoseDecryptException e) {
					failure.addSuppressed(e); // this recipient/alg does not apply (wrong key, mode mismatch, malformed header); try the next candidate
				} catch (IllegalArgumentException | IllegalStateException e) {
					failure.addSuppressed(new JoseDecryptException("Malformed recipient: " + e.getMessage(), e)); // defense in depth: an alg tripping over a malformed header must not abort the loop
				}
			}
		}
		throw failure;
	}

	// the decrypted payload as text; a successfully authenticated payload that is not UTF-8 is a content error shared by all recipients
	private static String payloadString(byte[] payload) throws DecryptCiphertextException {
		try {
			return Utf8.strictString(payload);
		} catch (IllegalArgumentException e) {
			throw new DecryptCiphertextException("Payload is not valid UTF-8", e);
		}
	}

	// the recipients whose JOSE Header carries the given kid; exactly one is expected
	private List<com.google.gson.JsonElement> recipientsWithKid(String kid, JsonObject sharedHeader) throws JoseDecryptException {
		var matches = recipients.asList().stream().filter(r -> {
			var recipientHeader = r.getAsJsonObject().has("header") ? r.getAsJsonObject().getAsJsonObject("header") : new JsonObject();
			var kidHeader = recipientHeader.has("kid") ? recipientHeader.get("kid") : sharedHeader.get("kid");
			return kidHeader != null && kidHeader.isJsonPrimitive() && kidHeader.getAsJsonPrimitive().isString() && kid.equals(kidHeader.getAsString());
		}).toList();
		if (matches.isEmpty()) {
			throw new JoseDecryptException("No recipient with kid '" + kid + "'");
		} else if (matches.size() > 1) {
			throw new JoseDecryptException("Ambiguous kid '" + kid + "': " + matches.size() + " recipients");
		}
		return matches;
	}
}
