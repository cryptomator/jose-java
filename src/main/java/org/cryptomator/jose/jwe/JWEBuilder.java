package org.cryptomator.jose.jwe;

import com.google.gson.JsonObject;

public sealed interface JWEBuilder permits SimpleJWEBuilder, ComplexJWEBuilder {

	static SimpleJWEBuilder withPayload(String payload) {
		return new SimpleJWEBuilder(payload, new JsonObject());
	}

}
