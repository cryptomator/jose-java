package org.cryptomator.jose.builder;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.EncryptionAlg;
import org.cryptomator.jose.util.JsonHelper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/// @param protectedHeader BASE64URL(UTF8(JWE Protected Header))
///	@param unprotectedHeader JWE Shared Unprotected Header
/// @param recipients JWE Per-Recipient Unprotected Header and encrypted keys
/// @param iv BASE64URL(JWE Initialization Vector)
/// @param ciphertext BASE64URL(JWE Ciphertext)
/// @param tag BASE64URL(JWE Authentication Tag)
/// @param aad BASE64URL(JWE AAD)
record EncryptedJWEImpl(String protectedHeader, JsonObject unprotectedHeader, JsonArray recipients, String iv, String ciphertext, String tag, String aad) implements SimpleEncryptedJWE {

	// https://www.rfc-editor.org/rfc/rfc7516#section-5.1
	static EncryptedJWEImpl build(SimpleBuilder builder, Enc enc, EncryptionAlg alg) {
		var base64url = Base64.getUrlEncoder().withoutPadding();

		// generate cek:
		var cek = enc.generateCek();

		// prepare recipient object:
		var algResult = alg.encrypt(cek);
		var recipientsArray = new JsonArray(1);
		var recipientObj = new JsonObject();
		recipientObj.addProperty("encrypted_key", base64url.encodeToString(algResult.encryptedKey()));
		recipientsArray.add(recipientObj);

		// prepare protected header:
		var protectedHeader = JsonHelper.union(algResult.recipientSpecificHeader(), builder.protectedHeader());
		protectedHeader.addProperty("enc", enc.encValue());
		var encodedProtectedHeader = base64url.encodeToString(protectedHeader.toString().getBytes(StandardCharsets.UTF_8));

		// encrypt payload:
		return encrypt(enc, cek, encodedProtectedHeader, recipientsArray, new JsonObject(), builder.payload(), "");
	}

	static EncryptedJWEImpl build(ComplexBuilder builder, Enc enc, EncryptionAlg... algs) {
		var base64url = Base64.getUrlEncoder().withoutPadding();

		// generate and encrypt cek:
		var cek = enc.generateCek();

		// prepare recipient objects:
		JsonArray recipientsArray = new JsonArray();
		for (EncryptionAlg alg : algs) {
			var algResult = alg.encrypt(cek);
			var recipientObj = new JsonObject();
			recipientObj.addProperty("encrypted_key", base64url.encodeToString(algResult.encryptedKey()));
			recipientObj.add("header", algResult.recipientSpecificHeader());
			recipientsArray.add(recipientObj);
		}

		// TODO: if all recipients use the same alg, move it to protected header! see https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6

		// prepare protected header:
		var protectedHeader = builder.protectedHeader().deepCopy();
		protectedHeader.addProperty("enc", enc.encValue());
		var encodedProtectedHeader = base64url.encodeToString(protectedHeader.toString().getBytes(StandardCharsets.UTF_8));

		// encrypt payload:
		return encrypt(enc, cek, encodedProtectedHeader, recipientsArray, builder.unprotectedHeader(), builder.payload(), builder.aad());
	}

	static EncryptedJWEImpl encrypt(Enc enc, byte[] cek, String protectedHeader, JsonArray recipients, JsonObject unprotectedHeader, String payload, String aad) {
		var base64url = Base64.getUrlEncoder().withoutPadding();

		var iv = enc.generateIv();
		var encodedIv = base64url.encodeToString(iv);
		var combinedAad = protectedHeader + (aad.isEmpty() ? "" : "." + aad);
		var encResult = enc.encrypt(cek, iv, combinedAad.getBytes(StandardCharsets.US_ASCII), payload.getBytes(StandardCharsets.UTF_8));
		var encodedCiphertext = base64url.encodeToString(encResult.ciphertext());
		var encodedTag = base64url.encodeToString(encResult.tag());

		// assemble JWE:
		return new EncryptedJWEImpl(protectedHeader, unprotectedHeader, recipients, encodedIv, encodedCiphertext, encodedTag, aad);
	}

	@Override
	public String toCompactSerialization() {
		if (recipients.size() != 1) {
			throw new UnsupportedOperationException("Compact serialization is only supported for JWEs with exactly one recipient.");
		}
		if (!aad.isEmpty()) {
			throw new UnsupportedOperationException("Compact serialization is not supported for AAD.");
		}
		var recipient = recipients.get(0).getAsJsonObject();
		var encryptedKey = recipient.get("encrypted_key").getAsString();
		return protectedHeader + "." + encryptedKey + "." + iv + "." + ciphertext + "." + tag;
	}

	@Override
	public String toJsonSerialization() {
		return toJson().toString();
	}

	@Override
	public String toFlattenedJsonSerialization() {
		if (recipients.size() != 1) {
			throw new UnsupportedOperationException("Flattened serialization is only supported for JWEs with exactly one recipient.");
		}
		return toFlattenedJson().toString();
	}

	private JsonObject toJson() {
		JsonObject json = new JsonObject();
		json.addProperty("protected", protectedHeader);
		if (!unprotectedHeader.isEmpty()) {
			json.add("unprotected", unprotectedHeader);
		}
		json.add("recipients", recipients);
		if (!aad.isEmpty()) {
			json.addProperty("aad", aad);
		}
		json.addProperty("iv", iv);
		json.addProperty("ciphertext", ciphertext);
		json.addProperty("tag", tag);
		return json;
	}

	private JsonObject toFlattenedJson() {
		var recipient = recipients.get(0).getAsJsonObject();
		JsonObject json = new JsonObject();
		json.addProperty("protected", protectedHeader);
		if (!unprotectedHeader.isEmpty()) {
			json.add("unprotected", unprotectedHeader);
		}
		if (recipient.has("header")) {
			json.add("header", recipient.get("header").getAsJsonObject());
		}
		json.addProperty("encrypted_key", recipient.get("encrypted_key").getAsString());
		if (!aad.isEmpty()) {
			json.addProperty("aad", aad);
		}
		json.addProperty("iv", iv);
		json.addProperty("ciphertext", ciphertext);
		json.addProperty("tag", tag);
		return json;
	}
}
