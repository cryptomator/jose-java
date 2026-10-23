package org.cryptomator.jose.parser;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import org.cryptomator.jose.JoseParseException;
import org.cryptomator.jose.util.CriticalHeaderPolicy;
import org.cryptomator.jose.util.JsonHelper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

/// Parses a JWE in any of the three serializations ([RFC 7516, Section 7](https://www.rfc-editor.org/rfc/rfc7516#section-7)) into a [ParsedJWE].
/// Structural checks happen here (member types, JOSE Header rules incl. `crit`); cryptographic checks happen on decryption.
public class Parser {

	public static ParsedJWE parse(String token) throws JoseParseException {
		return parse(token, Set.of());
	}

	/// @param token The serialized JWE
	/// @param understoodCrit Extension header parameter names the caller understands and therefore accepts in `crit`, in addition to [CriticalHeaderPolicy#IMPLEMENTED_EXTENSIONS]
	/// @return The parsed, not yet decrypted JWE
	/// @throws JoseParseException if the token is malformed, violates the JOSE Header rules, or lists a critical extension that is not understood
	public static ParsedJWE parse(String token, Set<String> understoodCrit) throws JoseParseException {
		token = token.strip(); // whitespace around a JSON object is valid JSON text (e.g. a pretty-printed file); the compact form contains none anyway
		if (token.startsWith("{")) {
			JsonObject json;
			try {
				json = JsonParser.parseString(token).getAsJsonObject();
			} catch (JsonParseException | IllegalStateException e) {
				throw new JoseParseException("Invalid JSON format", e);
			}
			if (json.has("recipients")) {
				return parseGeneral(json, understoodCrit);
			} else if (json.has("encrypted_key")) {
				return parseFlattened(json, understoodCrit);
			} else {
				throw new JoseParseException("Invalid JWE format");
			}
		} else {
			return parseCompact(token, understoodCrit);
		}
	}

	public static ParsedJWE parseCompact(String token, Set<String> understoodCrit) throws JoseParseException {
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
		validateJoseHeaders(protectedHeader, unprotectedHeader, recipients, understoodCrit);
		return new ParsedJWE(protectedHeader, unprotectedHeader, recipients, iv, ciphertext, tag, aad);
	}

	public static ParsedJWE parseFlattened(JsonObject json, Set<String> understoodCrit) throws JoseParseException {
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
		return parseJson(recipients, json, understoodCrit);
	}

	public static ParsedJWE parseGeneral(JsonObject json, Set<String> understoodCrit) throws JoseParseException {
		var recipients = json.get("recipients");
		if (recipients == null || !recipients.isJsonArray()) {
			throw new JoseParseException("Missing or non-array 'recipients' field in JSON object");
		}
		return parseJson(recipients.getAsJsonArray(), json, understoodCrit);
	}

	private static ParsedJWE parseJson(JsonArray recipients, JsonObject json, Set<String> understoodCrit) throws JoseParseException {
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
			requireString(recipient, "encrypted_key");
			requireObject(recipient, "header");
		}
		var protectedHeader = optionalString(json, "protected");
		var unprotectedHeader = json.has("unprotected") ? requireObject(json, "unprotected") : new JsonObject();
		validateJoseHeaders(protectedHeader, unprotectedHeader, recipients, understoodCrit);
		var aad = optionalString(json, "aad");
		var iv = optionalString(json, "iv"); // absent for HPKE Integrated Encryption
		var tag = optionalString(json, "tag"); // absent for HPKE Integrated Encryption
		return new ParsedJWE(protectedHeader, unprotectedHeader, recipients, iv, requireString(json, "ciphertext"), tag, aad);
	}

	// RFC 7516 §4: per recipient, the JOSE Header (protected, shared unprotected and per-recipient header combined) must not contain duplicate names and must carry a string alg;
	// §4.1.3: zip is not supported by this library, so a compressed payload is rejected rather than returned still compressed;
	// §4.1.13: crit is integrity protected (protected header only), lists no registered names, only understood names, and only names present in the JOSE Header
	private static void validateJoseHeaders(String protectedHeader, JsonObject unprotectedHeader, JsonArray recipients, Set<String> understoodCrit) throws JoseParseException {
		try {
			var decodedProtectedHeader = decodeProtectedHeader(protectedHeader);
			var understood = new HashSet<>(CriticalHeaderPolicy.IMPLEMENTED_EXTENSIONS);
			understood.addAll(understoodCrit);
			var crit = CriticalHeaderPolicy.validate(decodedProtectedHeader, understood);
			var sharedHeader = JsonHelper.disjointUnion(decodedProtectedHeader, unprotectedHeader);
			for (var r : recipients) {
				var recipient = r.getAsJsonObject();
				var recipientHeader = recipient.has("header") ? recipient.get("header").getAsJsonObject() : new JsonObject();
				var joseHeader = JsonHelper.disjointUnion(recipientHeader, sharedHeader);
				if (!joseHeader.has("alg") || !joseHeader.get("alg").isJsonPrimitive() || !joseHeader.getAsJsonPrimitive("alg").isString()) {
					throw new JoseParseException("Missing or non-string alg header parameter");
				}
				if (joseHeader.has("zip")) {
					throw new JoseParseException("Unsupported header parameter: zip");
				}
				if (unprotectedHeader.has("crit") || recipientHeader.has("crit")) {
					throw new JoseParseException("crit must only occur in the protected header");
				}
				CriticalHeaderPolicy.ensurePresent(crit, joseHeader);
			}
		} catch (IllegalArgumentException e) {
			throw new JoseParseException(e.getMessage(), e);
		}
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

	// the member's string value, requiring it to be present
	private static String requireString(JsonObject json, String member) throws JoseParseException {
		var value = json.get(member);
		if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
			throw new JoseParseException("Missing or non-string '" + member + "' field");
		}
		return value.getAsString();
	}

	// the member's string value, or an empty string if absent
	private static String optionalString(JsonObject json, String member) throws JoseParseException {
		return json.has(member) ? requireString(json, member) : "";
	}

	// the member as an object, or null if absent
	private static JsonObject requireObject(JsonObject json, String member) throws JoseParseException {
		JsonElement value = json.get(member);
		if (value == null) {
			return null;
		} else if (!value.isJsonObject()) {
			throw new JoseParseException("Non-object '" + member + "' field");
		}
		return value.getAsJsonObject();
	}

}
