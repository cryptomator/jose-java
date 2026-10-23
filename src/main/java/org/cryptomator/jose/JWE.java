package org.cryptomator.jose;

import org.cryptomator.jose.jwe.JWEBuilder;
import org.cryptomator.jose.jwe.SimpleJWEBuilder;
import org.cryptomator.jose.jwe.ParsedJWE;
import org.cryptomator.jose.jwe.JWEParser;

import java.util.Set;

///
/// Usage example with HPKE-2:
///
/// {@snippet :
///// create key pair:
///var ecKeyGen = java.security.KeyPairGenerator.getInstance("EC");
///ecKeyGen.initialize(new ECGenParameterSpec("secp521r1"));
///var keyPair = ecKeyGen.generateKeyPair();
///
///// encrypt to public key (HPKE Integrated Encryption):
///var jwe = JWE.build("payload")
///		.encrypt(Alg.hpke2(keyPair.getPublic()))
///		.toCompactSerialization();
///
///// decrypt with private key:
///var parsed = JWE.parse(jwe).decrypt(Alg.hpke2(keyPair.getPrivate()));
/// }
public interface JWE {

	/// Parses a JWE in compact, flattened or general JSON serialization.
	///
	/// @param token The serialized JWE
	/// @param understoodCrit Extension header parameter names the caller understands and therefore accepts in `crit`
	///                       ([RFC 7516, Section 4.1.13](https://www.rfc-editor.org/rfc/rfc7516#section-4.1.13)); extensions implemented by this library (e.g. `ek`) need not be listed
	/// @return The parsed, not yet decrypted JWE
	/// @throws JoseParseException if the token is malformed, violates the JOSE Header rules, or lists a critical extension that is not understood
	static ParsedJWE parse(String token, String... understoodCrit) throws JoseParseException {
		return JWEParser.parse(token, Set.of(understoodCrit));
	}

	static SimpleJWEBuilder build(String payload) {
		return JWEBuilder.withPayload(payload);
	}

}
