package org.cryptomator.jose.parser;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import org.cryptomator.jose.JoseParseException;

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
		var parts = token.split("\\.");
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
		if (!json.has("iv")) {
			throw new JoseParseException("Missing 'iv' field in JSON object");
		}
		if (!json.has("ciphertext")) {
			throw new JoseParseException("Missing 'ciphertext' field in JSON object");
		}
		if (!json.has("tag")) {
			throw new JoseParseException("Missing 'tag' field in JSON object");
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
		var aad = json.has("aad") ? json.get("aad").getAsString() : "";
		return new ParsedJWE(protectedHeader, unprotectedHeader, recipients, json.get("iv").getAsString(), json.get("ciphertext").getAsString(), json.get("tag").getAsString(), aad);
	}


}
