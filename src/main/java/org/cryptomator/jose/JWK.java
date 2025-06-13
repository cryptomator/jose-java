package org.cryptomator.jose;

import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import org.cryptomator.jose.util.ECHelper;

import java.security.Key;

/// JSON Web Key (JWK) Utility
/// @see [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)
/// @see [IANA JWK Types](https://www.iana.org/assignments/jose/jose.xhtml#web-key-types)
/// @see [IANA JWK Parameters](https://www.iana.org/assignments/jose/jose.xhtml#web-key-parameters)
public interface JWK {

	static Key parse(String json) throws JoseParseException {
		try {
			var jsonObj = JsonParser.parseString(json);
			if (!jsonObj.isJsonObject()) {
				throw new JoseParseException("JWK JSON must be an object");
			}
			return parse(jsonObj.getAsJsonObject());
		} catch (JsonParseException e) {
			throw new JoseParseException("Failed to parse JWK JSON", e);
		}
	}

	static Key parse(JsonObject json) throws JoseParseException {
		if (json == null || !json.has("kty")) {
			throw new JoseParseException("JWK JSON must contain 'kty' field");
		}
		String kty = json.get("kty").getAsString();
		// see https://www.iana.org/assignments/jose/jose.xhtml#web-key-types
		return switch (kty) {
			case "EC" -> ECHelper.fromJwk(json);
			// TODO: add further key types as needed
			default -> throw new JoseParseException("Unsupported JWK key type: " + kty);
		};
	}
}
