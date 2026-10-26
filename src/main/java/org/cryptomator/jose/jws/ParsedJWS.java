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
import java.util.Objects;

/// A parsed, not yet verified JWS in compact serialization. Instances are only created by [JWSParser] and have passed the JOSE Header checks (incl. `crit`).
/// Nothing here is authenticated until [#verify] succeeds.
public final class ParsedJWS {

	private final String encodedHeader;
	private final String encodedPayload;
	private final String encodedSignature;

	// only JWSParser creates instances, so that every ParsedJWS has passed the structural and JOSE Header checks
	ParsedJWS(String encodedHeader, String encodedPayload, String encodedSignature) {
		this.encodedHeader = Objects.requireNonNull(encodedHeader);
		this.encodedPayload = Objects.requireNonNull(encodedPayload);
		this.encodedSignature = Objects.requireNonNull(encodedSignature);
	}

	/// @return BASE64URL(UTF8(JWS Protected Header)), the first segment as received
	public String encodedHeader() {
		return encodedHeader;
	}

	/// @return BASE64URL(JWS Payload), the second segment as received
	public String encodedPayload() {
		return encodedPayload;
	}

	/// @return BASE64URL(JWS Signature), the third segment as received
	public String encodedSignature() {
		return encodedSignature;
	}

	/// The decoded JWS Protected Header. NOT authenticated until [#verify] succeeds.
	///
	/// @return The protected header
	public JsonObject parsedProtectedHeader() {
		try {
			return JsonHelper.parseObject(Utf8.strictString(Base64Url.decode(encodedHeader)));
		} catch (JoseParseException e) {
			throw new AssertionError("JWSParser has already decoded this header", e);
		}
	}

	/// The payload before verification, for inspection only. Trust its content only after [#verify] succeeded.
	///
	/// @return The decoded, unverified payload
	public String unverifiedPayload() {
		return Utf8.strictString(Base64Url.decode(encodedPayload));
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
		var signingInput = Ascii.strictBytes(encodedHeader + "." + encodedPayload);
		var expected = Base64Url.decode(encodedSignature);
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

	@Override
	public boolean equals(Object obj) {
		return obj instanceof ParsedJWS other && encodedHeader.equals(other.encodedHeader) && encodedPayload.equals(other.encodedPayload) && encodedSignature.equals(other.encodedSignature);
	}

	@Override
	public int hashCode() {
		return Objects.hash(encodedHeader, encodedPayload, encodedSignature);
	}

	@Override
	public String toString() {
		return encodedHeader + "." + encodedPayload + "." + encodedSignature;
	}

}
