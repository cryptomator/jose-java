package org.cryptomator.jose;

import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import org.cryptomator.jose.hpke.XwingProvider;
import org.cryptomator.jose.util.ECHelper;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/// JSON Web Key (JWK) Utility, see [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517),
/// [IANA JWK Types](https://www.iana.org/assignments/jose/jose.xhtml#web-key-types),
/// and [IANA JWK Parameters](https://www.iana.org/assignments/jose/jose.xhtml#web-key-parameters)
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
		if (json == null) {
			throw new JoseParseException("JWK JSON must be an object");
		}
		String kty = requireString(json, "kty");
		// see https://www.iana.org/assignments/jose/jose.xhtml#web-key-types
		return switch (kty) {
			case "EC" -> ECHelper.fromJwk(json);
			case "AKP" -> akpFromJwk(json);
			// TODO: add further key types as needed
			default -> throw new JoseParseException("Unsupported JWK key type: " + kty);
		};
	}

	/// Parses an Algorithm Key Pair JWK as defined in [RFC 9964, Section 3](https://www.rfc-editor.org/rfc/rfc9964#section-3), whose required `alg` parameter
	/// identifies the key's algorithm. `pub`/`priv` contain the KEM's `SerializePublicKey()`/`SerializePrivateKey()` output (for X-Wing: the raw 1216-byte
	/// public key and the 32-byte seed). Returns the private key if `priv` is present, the public key otherwise.
	private static Key akpFromJwk(JsonObject json) throws JoseParseException {
		var alg = requireString(json, "alg");
		if (!alg.equals("HPKE-9") && !alg.equals("HPKE-9-KE")) { // both "HPKE-9" and "HPKE-9-KE" use the MLKEM768-X25519 (X-Wing) KEM
			throw new JoseParseException("Unsupported AKP algorithm: " + alg);
		}
		try {
			var kf = KeyFactory.getInstance("X-Wing", XwingProvider.INSTANCE);
			if (json.has("priv")) {
				return kf.generatePrivate(rawKeySpec(requireString(json, "priv")));
			} else if (json.has("pub")) {
				return kf.generatePublic(rawKeySpec(requireString(json, "pub")));
			} else {
				throw new JoseParseException("AKP JWK must contain 'pub' or 'priv' field");
			}
		} catch (NoSuchAlgorithmException e) {
			throw new AssertionError("Custom X-Wing provider must support X-Wing key factory", e);
		} catch (IllegalArgumentException | InvalidKeySpecException e) {
			throw new JoseParseException("Invalid AKP key material", e);
		}
	}

	/// Returns the value of the given member, requiring it to be present and a JSON string.
	private static String requireString(JsonObject json, String key) throws JoseParseException {
		var element = json.get(key);
		if (element == null || !element.isJsonPrimitive() || !element.getAsJsonPrimitive().isString()) {
			throw new JoseParseException("JWK JSON must contain a string '" + key + "' field");
		}
		return element.getAsString();
	}

	private static EncodedKeySpec rawKeySpec(String base64url) {
		return new EncodedKeySpec(Base64.getUrlDecoder().decode(base64url)) {
			@Override
			public String getFormat() {
				return "RAW";
			}
		};
	}

}
