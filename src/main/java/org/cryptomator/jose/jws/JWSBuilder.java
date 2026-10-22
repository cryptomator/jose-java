package org.cryptomator.jose.jws;

import com.google.gson.JsonObject;
import org.cryptomator.jose.MacAlg;
import org.cryptomator.jose.util.Ascii;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

/// Builds a JWS in compact serialization, see [RFC 7515, Section 5.1](https://www.rfc-editor.org/rfc/rfc7515#section-5.1).
///
/// @param payload The JWS Payload
/// @param protectedHeader Caller-supplied JWS Protected Header parameters (e.g. `typ`, `kid`); `alg` is added when signing
public record JWSBuilder(String payload, JsonObject protectedHeader) {

	public JWSBuilder {
		Objects.requireNonNull(payload, "payload");
		protectedHeader = protectedHeader == null ? new JsonObject() : protectedHeader.deepCopy();
	}

	public static JWSBuilder withPayload(String payload) {
		return new JWSBuilder(payload, new JsonObject());
	}

	/// @param protectedHeader Header parameters replacing the current ones
	/// @return A copy of this builder with the given protected header
	public JWSBuilder withProtectedHeader(JsonObject protectedHeader) {
		return new JWSBuilder(payload, protectedHeader);
	}

	/// Signs the payload, producing the compact serialization `BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)`.
	///
	/// @param alg The MAC algorithm, whose name becomes the `alg` header parameter
	/// @return The JWS in compact serialization
	/// @throws IllegalArgumentException if the caller-supplied header contains `alg`, or the unsupported `b64` parameter ([RFC 7797](https://www.rfc-editor.org/rfc/rfc7797))
	public String sign(MacAlg alg) throws IllegalArgumentException {
		if (protectedHeader.has("alg")) {
			throw new IllegalArgumentException("Header parameter 'alg' is derived from the signing algorithm and must not be set by the caller");
		}
		if (protectedHeader.has("b64")) {
			throw new IllegalArgumentException("Unsupported header parameter: b64");
		}
		var base64url = Base64.getUrlEncoder().withoutPadding();
		var header = new JsonObject();
		header.addProperty("alg", alg.name());
		protectedHeader.entrySet().forEach(e -> header.add(e.getKey(), e.getValue()));
		var encodedHeader = base64url.encodeToString(header.toString().getBytes(StandardCharsets.UTF_8));
		var encodedPayload = base64url.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
		var signature = alg.sign(Ascii.strictBytes(encodedHeader + "." + encodedPayload));
		return encodedHeader + "." + encodedPayload + "." + base64url.encodeToString(signature);
	}

}
