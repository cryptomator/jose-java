package org.cryptomator.jose.builder;

import com.google.gson.JsonObject;

public sealed interface Builder permits SimpleBuilder, ComplexBuilder {

	static SimpleBuilder withPayload(String payload) {
		return new SimpleBuilder(payload, new JsonObject());
	}

}
