package org.cryptomator.jose.jwe;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.IntegratedEncryptionAlg;
import org.cryptomator.jose.Recipient;
import org.cryptomator.jose.util.Ascii;
import org.cryptomator.jose.util.Crit;
import org.cryptomator.jose.util.JsonHelper;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/// @param protectedHeader BASE64URL(UTF8(JWE Protected Header))
///	@param unprotectedHeader JWE Shared Unprotected Header
/// @param recipients JWE Per-Recipient Unprotected Header and encrypted keys
/// @param iv BASE64URL(JWE Initialization Vector)
/// @param ciphertext BASE64URL(JWE Ciphertext)
/// @param tag BASE64URL(JWE Authentication Tag)
/// @param aad BASE64URL(JWE AAD)
record EncryptedJWEImpl(String protectedHeader, JsonObject unprotectedHeader, JsonArray recipients, String iv, String ciphertext, String tag, String aad) implements SimpleEncryptedJWE {

	private static final String PROTECTED = "protected header";
	private static final String SHARED_UNPROTECTED = "shared unprotected header";
	private static final String PER_RECIPIENT = "per-recipient header";
	private static final String ALG_GENERATED = "alg-generated recipient header";

	// https://www.rfc-editor.org/rfc/rfc7516#section-5.1, single recipient without AAD or shared unprotected header: all header params go into the protected header
	static EncryptedJWEImpl build(SimpleJWEBuilder builder, Enc enc, Recipient recipient) {
		var base64url = Base64.getUrlEncoder().withoutPadding();

		// generate cek:
		var cek = enc.generateCek();
		try {
			// the alg sees the complete JOSE Header (minus its own output), so e.g. apu/apv from the recipient header reach the KDF:
			var protectedHeader = protectedHeaderWithEnc(builder.protectedHeader(), enc);
			var visibleHeader = disjointUnion(recipient.header(), PER_RECIPIENT, protectedHeader, PROTECTED);
			var algResult = recipient.alg().encrypt(visibleHeader, cek);

			// prepare recipient object:
			var recipientsArray = new JsonArray(1);
			var recipientObj = new JsonObject();
			recipientObj.addProperty("encrypted_key", base64url.encodeToString(algResult.encryptedKey()));
			recipientsArray.add(recipientObj);

			// finalize protected header by folding the recipient's params into it:
			Crit.Builder.rejectUnprotected(recipient.header(), PER_RECIPIENT);
			var recipientHeader = disjointUnion(algResult.recipientSpecificHeader(), ALG_GENERATED, recipient.header(), PER_RECIPIENT);
			protectedHeader = disjointUnion(recipientHeader, PER_RECIPIENT, protectedHeader, PROTECTED);
			Crit.Builder.ensurePresent(Crit.Builder.validate(protectedHeader), protectedHeader); // RFC 7515 Section 4.1.11: a producer must only list params that are present
			var encodedProtectedHeader = base64url.encodeToString(protectedHeader.toString().getBytes(StandardCharsets.UTF_8));

			// encrypt payload:
			return encrypt(enc, cek, encodedProtectedHeader, recipientsArray, new JsonObject(), builder.payload(), "");
		} finally {
			Arrays.fill(cek, (byte) 0x00);
		}
	}

	// https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1: per-recipient params stay in each recipient's own header
	static EncryptedJWEImpl build(ComplexJWEBuilder builder, Enc enc, Recipient... recipients) {
		if (recipients.length == 0) {
			throw new IllegalArgumentException("At least one recipient is required");
		}
		var base64url = Base64.getUrlEncoder().withoutPadding();

		// generate and encrypt cek:
		var cek = enc.generateCek();
		try {
			// prepare shared header (protected + shared unprotected), which every recipient's header must be disjoint with:
			var protectedHeader = protectedHeaderWithEnc(builder.protectedHeader(), enc);
			Crit.Builder.rejectUnprotected(builder.unprotectedHeader(), SHARED_UNPROTECTED);
			var sharedHeader = disjointUnion(protectedHeader, PROTECTED, builder.unprotectedHeader(), SHARED_UNPROTECTED);
			var crit = Crit.Builder.validate(protectedHeader);

			// prepare recipient objects:
			JsonArray recipientsArray = new JsonArray();
			for (Recipient recipient : recipients) {
				Crit.Builder.rejectUnprotected(recipient.header(), PER_RECIPIENT);
				var visibleHeader = disjointUnion(recipient.header(), PER_RECIPIENT, sharedHeader, "protected or shared unprotected header");
				var algResult = recipient.alg().encrypt(visibleHeader, cek);
				var recipientHeader = disjointUnion(algResult.recipientSpecificHeader(), ALG_GENERATED, recipient.header(), PER_RECIPIENT);
				var joseHeader = disjointUnion(recipientHeader, ALG_GENERATED, sharedHeader, "protected or shared unprotected header"); // e.g. rejects a caller-supplied protected 'alg'
				Crit.Builder.ensurePresent(crit, joseHeader); // RFC 7515 Section 4.1.11: every critical param must be present in this recipient's JOSE Header
				var recipientObj = new JsonObject();
				recipientObj.addProperty("encrypted_key", base64url.encodeToString(algResult.encryptedKey()));
				recipientObj.add("header", recipientHeader);
				recipientsArray.add(recipientObj);
			}

			// finalize protected header:
			// TODO: if all recipients use the same alg, move it to protected header! see https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6
			var encodedProtectedHeader = base64url.encodeToString(protectedHeader.toString().getBytes(StandardCharsets.UTF_8));

			// encrypt payload:
			return encrypt(enc, cek, encodedProtectedHeader, recipientsArray, builder.unprotectedHeader(), builder.payload(), builder.aad());
		} finally {
			Arrays.fill(cek, (byte) 0x00);
		}
	}

	// https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5
	static EncryptedJWEImpl build(ComplexJWEBuilder builder, IntegratedEncryptionAlg alg) {
		var base64url = Base64.getUrlEncoder().withoutPadding();

		// prepare protected header:
		Crit.Builder.rejectUnprotected(builder.unprotectedHeader(), SHARED_UNPROTECTED);
		var userHeader = disjointUnion(builder.protectedHeader(), PROTECTED, builder.unprotectedHeader(), SHARED_UNPROTECTED);
		if (userHeader.has("enc") || userHeader.has("ek")) {
			throw new IllegalArgumentException("enc and ek headers must not be present for Integrated Encryption");
		}
		var algHeader = alg.generatedProtectedHeader(); // alg, and psk_id in mode_psk
		for (var generated : algHeader.keySet()) {
			if (userHeader.has(generated)) {
				throw new IllegalArgumentException("Header parameter '" + generated + "' is derived from the algorithm and must not be set by the caller"); // in either header: the parser rejects duplicates
			}
		}
		var protectedHeader = disjointUnion(algHeader, ALG_GENERATED, builder.protectedHeader(), PROTECTED);
		Crit.Builder.ensurePresent(Crit.Builder.validate(protectedHeader), JsonHelper.union(protectedHeader, builder.unprotectedHeader()));
		var encodedProtectedHeader = base64url.encodeToString(protectedHeader.toString().getBytes(StandardCharsets.UTF_8));

		// prepare aad (input to the HPKE seal, so it must be final before encrypting):
		var combinedAad = encodedProtectedHeader + (builder.aad().isEmpty() ? "" : "." + builder.aad());

		// encrypt payload:
		var sealed = alg.seal(builder.payload().getBytes(StandardCharsets.UTF_8), Ascii.strictBytes(combinedAad));

		// assemble JWE (the encapsulated secret is the encrypted key; iv and tag are empty):
		var recipientObj = new JsonObject();
		recipientObj.addProperty("encrypted_key", base64url.encodeToString(sealed.encapsulation()));
		var recipientsArray = new JsonArray(1);
		recipientsArray.add(recipientObj);
		return new EncryptedJWEImpl(encodedProtectedHeader, builder.unprotectedHeader(), recipientsArray, "", base64url.encodeToString(sealed.ciphertext()), "", builder.aad());
	}

	// the caller's protected header plus the enc param, which is derived from the Enc argument and therefore must not be supplied by the caller
	private static JsonObject protectedHeaderWithEnc(JsonObject userProtectedHeader, Enc enc) {
		if (userProtectedHeader.has("enc")) {
			throw new IllegalArgumentException("Header parameter 'enc' is derived from the content encryption algorithm and must not be set in the " + PROTECTED);
		}
		var protectedHeader = userProtectedHeader.deepCopy();
		protectedHeader.addProperty("enc", enc.encValue());
		return protectedHeader;
	}

	// RFC 7516 Section 4 requires the header parameter names across the protected, shared unprotected and per-recipient headers to be disjoint;
	// unlike the parser-side JsonHelper.disjointUnion, this names the colliding locations in the error message
	private static JsonObject disjointUnion(JsonObject a, String nameA, JsonObject b, String nameB) {
		var duplicate = a.keySet().stream().filter(b::has).findAny();
		if (duplicate.isPresent()) {
			throw new IllegalArgumentException("Header parameter '" + duplicate.get() + "' must not be present in both the " + nameA + " and the " + nameB);
		}
		return JsonHelper.union(a, b);
	}

	static EncryptedJWEImpl encrypt(Enc enc, byte[] cek, String protectedHeader, JsonArray recipients, JsonObject unprotectedHeader, String payload, String aad) {
		var base64url = Base64.getUrlEncoder().withoutPadding();

		var iv = enc.generateIv();
		var encodedIv = base64url.encodeToString(iv);
		var combinedAad = protectedHeader + (aad.isEmpty() ? "" : "." + aad);
		var encResult = enc.encrypt(cek, iv, Ascii.strictBytes(combinedAad), payload.getBytes(StandardCharsets.UTF_8));
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
		if (!iv.isEmpty()) {
			json.addProperty("iv", iv);
		}
		json.addProperty("ciphertext", ciphertext);
		if (!tag.isEmpty()) {
			json.addProperty("tag", tag);
		}
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
		if (!iv.isEmpty()) {
			json.addProperty("iv", iv);
		}
		json.addProperty("ciphertext", ciphertext);
		if (!tag.isEmpty()) {
			json.addProperty("tag", tag);
		}
		return json;
	}
}
