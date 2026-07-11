package org.cryptomator.jose;

import org.cryptomator.jose.builder.Builder;
import org.cryptomator.jose.builder.SimpleBuilder;
import org.cryptomator.jose.parser.ParsedJWE;
import org.cryptomator.jose.parser.Parser;

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

	static ParsedJWE parse(String token) throws JoseParseException {
		return Parser.parse(token);
	}

	static SimpleBuilder build(String payload) {
		return Builder.withPayload(payload);
	}

}
