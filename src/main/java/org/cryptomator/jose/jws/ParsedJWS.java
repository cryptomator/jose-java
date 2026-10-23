package org.cryptomator.jose.jws;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.cryptomator.jose.JoseVerifyException;
import org.cryptomator.jose.MacAlg;
import org.cryptomator.jose.util.Ascii;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/// A parsed, not yet verified JWS in compact serialization. Instances produced by [JWSParser] have passed the JOSE Header checks (incl. `crit`).
///
/// @param protectedHeader BASE64URL(UTF8(JWS Protected Header))
/// @param payload BASE64URL(JWS Payload)
/// @param signature BASE64URL(JWS Signature)
public record ParsedJWS(String protectedHeader, String payload, String signature) {

	public JsonObject parsedProtectedHeader() {
		var decoded = new String(Base64.getUrlDecoder().decode(protectedHeader), StandardCharsets.UTF_8);
		return JsonParser.parseString(decoded).getAsJsonObject();
	}

	/// The payload before verification, for inspection only. Trust its content only after [#verify] succeeded.
	///
	/// @return The decoded, unverified payload
	public String unverifiedPayload() {
		return new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8);
	}

	/// Verifies the signature with the provided algorithms whose name matches the `alg` header, e.g. several HS256 instances during key rotation.
	///
	/// @param algs The candidate MAC algorithms
	/// @return The verified JWS
	/// @throws JoseVerifyException if no algorithm matches the `alg` header or the signature is invalid
	public VerifiedJWS verify(MacAlg... algs) throws JoseVerifyException {
		var header = parsedProtectedHeader();
		var algValue = header.get("alg").getAsString();
		var signingInput = Ascii.strictBytes(protectedHeader + "." + payload);
		var expected = Base64.getUrlDecoder().decode(signature);
		var algMatched = false;
		for (var alg : algs) {
			if (!algValue.equals(alg.name())) {
				continue;
			}
			algMatched = true;
			if (MessageDigest.isEqual(alg.sign(signingInput), expected)) {
				return new VerifiedJWS(unverifiedPayload(), header);
			}
		}
		if (algMatched) {
			throw new JoseVerifyException("Invalid signature");
		} else {
			throw new JoseVerifyException("No provided algorithm matches alg '" + algValue + "'");
		}
	}

}
