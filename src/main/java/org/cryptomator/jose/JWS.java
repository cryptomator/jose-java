package org.cryptomator.jose;

import org.cryptomator.jose.jws.JWSBuilder;
import org.cryptomator.jose.jws.JWSParser;
import org.cryptomator.jose.jws.ParsedJWS;

import java.util.Set;

/// Entry point for JSON Web Signatures ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)) in compact serialization with MAC-based algorithms.
///
/// {@snippet :
///var token = JWS.build("{\"sub\":\"alice\"}")
///		.withProtectedHeader(header) // e.g. typ, kid
///		.sign(MacAlg.hs256(key));
///
///var verified = JWS.parse(token).verify(MacAlg.hs256(key));
///var payload = verified.payload();
/// }
public interface JWS {

	/// @param payload The JWS Payload (UTF-8 text, e.g. a JSON document)
	/// @return A builder for signing the payload
	static JWSBuilder build(String payload) {
		return JWSBuilder.withPayload(payload);
	}

	/// Parses a JWS in compact serialization without verifying it.
	///
	/// @param token The serialized JWS
	/// @param understoodCrit Extension header parameter names the caller understands and therefore accepts in `crit`
	///                       ([RFC 7515, Section 4.1.11](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11))
	/// @return The parsed, not yet verified JWS
	/// @throws JoseParseException if the token is malformed, violates the JOSE Header rules, or lists a critical extension that is not understood
	static ParsedJWS parse(String token, String... understoodCrit) throws JoseParseException {
		return JWSParser.parse(token, Set.of(understoodCrit));
	}

}
