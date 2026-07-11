package org.cryptomator.jose.parser;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.cryptomator.jose.DecryptionAlg;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.enc.DecryptCiphertextException;
import org.cryptomator.jose.util.JsonHelper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/// @param protectedHeader   JWE Protected Header
/// @param unprotectedHeader JWE Shared Unprotected Header
/// @param recipients        JWE Per-Recipient Unprotected Header and encrypted keys
/// @param iv                BASE64URL(JWE Initialization Vector)
/// @param ciphertext        BASE64URL(JWE Ciphertext)
/// @param tag               BASE64URL(JWE Authentication Tag)
/// @param aad               BASE64URL(JWE AAD)
public record ParsedJWE(String protectedHeader, JsonObject unprotectedHeader, JsonArray recipients, String iv,
						String ciphertext, String tag, String aad) {

	public JsonObject parsedProtectedHeader() {
		if (protectedHeader.isEmpty()) {
			return new JsonObject();
		}
		String decoded = new String(Base64.getUrlDecoder().decode(protectedHeader), StandardCharsets.UTF_8);
		return JsonParser.parseString(decoded).getAsJsonObject();
	}

	/// Decrypts the JWE, attempting the provided algorithms in order.
	///
	/// @throws JoseDecryptException if neither of the provided decryption methods is valid
	public DecryptedJWE decrypt(DecryptionAlg... algs) throws JoseDecryptException {
		var base64url = Base64.getUrlDecoder();
		var parsedProtectedHeader = parsedProtectedHeader();
		var sharedHeader = JsonHelper.disjointUnion(parsedProtectedHeader, unprotectedHeader);

		var combinedAad = protectedHeader + (aad.isEmpty() ? "" : "." + aad);
		var decodedIv = base64url.decode(iv);
		var decodedCiphertext = base64url.decode(ciphertext);
		var decodedTag = base64url.decode(tag);

		var failure = new JoseDecryptException("No matching recipient found for decryption.");
		for (var recipient : recipients) {
			var recipientJson = recipient.getAsJsonObject();
			var encryptedKey = base64url.decode(recipientJson.get("encrypted_key").getAsString());
			var perRecipientUnprotectedHeader = recipientJson.has("header")
					? recipientJson.get("header").getAsJsonObject()
					: new JsonObject();
			var combinedHeader = JsonHelper.disjointUnion(perRecipientUnprotectedHeader, sharedHeader);
			var algValue = combinedHeader.get("alg").getAsString();
			var parts = new DecryptionAlg.JweParts(encryptedKey, decodedIv, decodedCiphertext, decodedTag, combinedAad.getBytes(StandardCharsets.US_ASCII));
			for (var alg : algs) {
				if (!algValue.equals(alg.name())) {
					continue;
				}
				try {
					var payload = alg.decrypt(combinedHeader, parts);
					return new DecryptedJWE(new String(payload, StandardCharsets.UTF_8), parsedProtectedHeader, JsonHelper.union(unprotectedHeader, perRecipientUnprotectedHeader), aad);
				} catch (DecryptCiphertextException e) {
					throw e; // the key matched but the content is corrupt; other recipients share the same ciphertext and would fail identically
				} catch (JoseDecryptException e) {
					failure.addSuppressed(e); // this recipient/alg does not apply (wrong key, mode mismatch, malformed header); try the next candidate
				}
			}
		}
		throw failure;
	}
}
