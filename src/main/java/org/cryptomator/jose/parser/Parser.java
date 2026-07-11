package org.cryptomator.jose.parser;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import org.cryptomator.jose.JoseParseException;
import org.cryptomator.jose.util.JsonHelper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Parser {

	public static ParsedJWE parse(String token) throws JoseParseException {
		if (token.startsWith("{")) {
			JsonObject json;
			try {
				json = JsonParser.parseString(token).getAsJsonObject();
			} catch (JsonParseException e) {
				throw new JoseParseException("Invalid JSON format", e);
			}
			if (json.has("recipients")) {
				return parseGeneral(json);
			} else if (json.has("encrypted_key")) {
				return parseFlattened(json);
			} else {
				throw new JoseParseException("Invalid JWE format");
			}
		} else {
			return parseCompact(token);
		}
	}

	public static ParsedJWE parseCompact(String token) throws JoseParseException {
		var parts = token.split("\\.", -1); // -1 to keep empty parts (HPKE Integrated Encryption has empty iv and tag segments)
		if (parts.length != 5) {
			throw new JoseParseException("Invalid JWE compact serialization");
		}
		var protectedHeader = parts[0];
		var unprotectedHeader = new JsonObject();
		var recipients = new JsonArray();
		var recipient = new JsonObject();
		recipient.addProperty("encrypted_key", parts[1]);
		recipients.add(recipient);
		var aad = "";
		var iv = parts[2];
		var ciphertext = parts[3];
		var tag = parts[4];
		return new ParsedJWE(protectedHeader, unprotectedHeader, recipients, iv, ciphertext, tag, aad);
	}

	public static ParsedJWE parseFlattened(JsonObject json) throws JoseParseException {
		if (!json.has("header") && !json.has("protected") && !json.has("unprotected")) {
			throw new JoseParseException("Either of 'protected', 'unprotected', or 'header' must be present");
		}
		if (!json.has("encrypted_key")) {
			throw new JoseParseException("Missing 'encrypted_key' field in recipient object");
		}
		var recipient = new JsonObject();
		if (json.has("header")) {
			recipient.add("header", json.get("header"));
		}
		recipient.add("encrypted_key", json.get("encrypted_key"));
		var recipients = new JsonArray(1);
		recipients.add(recipient);
		return parseJson(recipients, json);
	}

	public static ParsedJWE parseGeneral(JsonObject json) throws JoseParseException {
		if (!json.has("recipients")) {
			throw new JoseParseException("Missing 'recipients' field in JSON object");
		}
		JsonArray recipients = json.getAsJsonArray("recipients");
		return parseJson(recipients, json);
	}

	private static ParsedJWE parseJson(JsonArray recipients, JsonObject json) throws JoseParseException {
		if (!json.has("ciphertext")) {
			throw new JoseParseException("Missing 'ciphertext' field in JSON object");
		}
		if (recipients.isEmpty()) {
			throw new JoseParseException("Empty 'recipients' array in JSON object");
		}
		for (var r : recipients) {
			if (!r.isJsonObject()) {
				throw new JoseParseException("Invalid recipient object in 'recipients' array");
			}
			var recipient = r.getAsJsonObject();
			if (!recipient.has("header") && !json.has("protected") && !json.has("unprotected")) {
				throw new JoseParseException("Either of 'protected', 'unprotected', or 'recipient.header' must be present");
			}
			if (!recipient.has("encrypted_key")) {
				throw new JoseParseException("Missing 'encrypted_key' field in recipient object");
			}
		}
		var protectedHeader = json.has("protected") ? json.get("protected").getAsString() : "";
		var unprotectedHeader = json.has("unprotected") ? json.get("unprotected").getAsJsonObject() : new JsonObject();
		// RFC 7516 §4: the JOSE Header (per recipient) must not contain duplicate parameter names across the protected, shared unprotected and per-recipient headers
		try {
			var sharedHeader = JsonHelper.disjointUnion(decodeProtectedHeader(protectedHeader), unprotectedHeader);
			for (var r : recipients) {
				var recipient = r.getAsJsonObject();
				var recipientHeader = recipient.has("header") ? recipient.get("header").getAsJsonObject() : new JsonObject();
				JsonHelper.disjointUnion(recipientHeader, sharedHeader); // called for its uniqueness check only; the merged header is rebuilt per recipient at decrypt time
			}
		} catch (IllegalArgumentException e) {
			throw new JoseParseException(e.getMessage(), e);
		}
		var aad = json.has("aad") ? json.get("aad").getAsString() : "";
		var iv = json.has("iv") ? json.get("iv").getAsString() : ""; // absent for HPKE Integrated Encryption
		var tag = json.has("tag") ? json.get("tag").getAsString() : ""; // absent for HPKE Integrated Encryption
		return new ParsedJWE(protectedHeader, unprotectedHeader, recipients, iv, json.get("ciphertext").getAsString(), tag, aad);
	}

	private static JsonObject decodeProtectedHeader(String protectedHeader) throws JoseParseException {
		if (protectedHeader.isEmpty()) {
			return new JsonObject();
		}
		try {
			var decoded = new String(Base64.getUrlDecoder().decode(protectedHeader), StandardCharsets.UTF_8);
			return JsonParser.parseString(decoded).getAsJsonObject();
		} catch (IllegalArgumentException | IllegalStateException | JsonParseException e) {
			// IllegalArgumentException: invalid base64url; IllegalStateException: valid JSON but not an object; JsonParseException: invalid JSON
			throw new JoseParseException("Invalid protected header", e);
		}
	}

}
