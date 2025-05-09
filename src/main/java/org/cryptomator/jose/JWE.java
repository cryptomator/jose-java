package org.cryptomator.jose;

import org.cryptomator.jose.builder.Builder;
import org.cryptomator.jose.builder.SimpleBuilder;
import org.cryptomator.jose.parser.ParsedJWE;
import org.cryptomator.jose.parser.Parser;

public interface JWE {

	static ParsedJWE parse(String token) throws JoseParseException {
		return Parser.parse(token);
	}

	static SimpleBuilder build(String payload) {
		return Builder.withPayload(payload);
	}

}
