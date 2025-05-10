package org.cryptomator.jose.builder;

import com.google.gson.JsonObject;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.EncryptionAlg;

public record ComplexBuilder(String payload, JsonObject protectedHeader, JsonObject unprotectedHeader, String aad) implements Builder {

	public ComplexBuilder withProtectedHeader(JsonObject protectedHeader) {
		return new ComplexBuilder(payload, protectedHeader, unprotectedHeader, aad);
	}

	public ComplexBuilder withUnprotectedHeader(JsonObject unprotectedHeader) {
		return new ComplexBuilder(payload, protectedHeader, unprotectedHeader, aad);
	}

	public SingleRecipientEncryptedJWE encrypt(Enc enc, EncryptionAlg alg) {
		return EncryptedJWEImpl.build(this, enc, alg);
	}

	public EncryptedJWE encrypt(Enc enc, EncryptionAlg... algs) {
		return EncryptedJWEImpl.build(this, enc, algs);
	}

	// TODO: add encrypt(HPKE... alg) method

}
