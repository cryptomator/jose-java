package org.cryptomator.jose.jws;

import com.google.gson.JsonObject;
import org.cryptomator.jose.JoseParseException;
import org.cryptomator.jose.JoseVerifyException;
import org.cryptomator.jose.MacAlg;
import org.cryptomator.jose.util.Ascii;
import org.cryptomator.jose.util.Base64Url;
import org.cryptomator.jose.util.JsonHelper;
import org.cryptomator.jose.util.Utf8;

import java.security.MessageDigest;

/// A parsed, not yet verified JWS in compact serialization. Instances produced by [JWSParser] have passed the JOSE Header checks (incl. `crit`).
///
/// @param protectedHeader BASE64URL(UTF8(JWS Protected Header))
/// @param payload BASE64URL(JWS Payload)
/// @param signature BASE64URL(JWS Signature)
public record ParsedJWS(String protectedHeader, String payload, String signature) {

	/// The decoded JWS Protected Header. NOT authenticated until [#verify] succeeds.
	///
	/// @return The protected header
	/// @throws IllegalArgumentException if the segment is not base64url, UTF-8 and a JSON object (cannot happen for instances produced by [JWSParser])
	public JsonObject parsedProtectedHeader() {
		try {
			return JsonHelper.parseObject(Utf8.strictString(Base64Url.decode(protectedHeader)));
		} catch (JoseParseException e) {
			throw new IllegalArgumentException("Malformed protected header", e);
		}
	}

	/// The payload before verification, for inspection only. Trust its content only after [#verify] succeeded.
	///
	/// @return The decoded, unverified payload
	public String unverifiedPayload() {
		return Utf8.strictString(Base64Url.decode(payload));
	}

	/// Verifies the signature with the provided algorithms whose name matches the `alg` header, e.g. several HS256 instances during key rotation.
	///
	/// Only the signature is verified. If the payload is a JWT claims set, the caller must still validate `exp`, `nbf`, `aud`, `iss` etc. ([RFC 7519, Section 7.2](https://www.rfc-editor.org/rfc/rfc7519#section-7.2)).
	///
	/// @param algs The candidate MAC algorithms
	/// @return The verified JWS
	/// @throws JoseVerifyException if no algorithm matches the `alg` header or the signature is invalid
	public VerifiedJWS verify(MacAlg... algs) throws JoseVerifyException {
		var header = parsedProtectedHeader();
		var algValue = header.get("alg").getAsString();
		var signingInput = Ascii.strictBytes(protectedHeader + "." + payload);
		var expected = Base64Url.decode(signature);
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
