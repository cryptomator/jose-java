package org.cryptomator.jose.builder;

import com.google.gson.JsonObject;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.IntegratedEncryptionAlg;
import org.cryptomator.jose.KeyEncryptionAlg;

public record SimpleBuilder(String payload, JsonObject protectedHeader) implements Builder {

	public SimpleBuilder withProtectedHeader(JsonObject protectedHeader) {
		return new SimpleBuilder(payload, protectedHeader);
	}

	public ComplexBuilder withUnprotectedHeader(JsonObject unprotectedHeader) {
		return new ComplexBuilder(payload, protectedHeader, unprotectedHeader, "");
	}

	public ComplexBuilder withAad(String aad) {
		return new ComplexBuilder(payload, protectedHeader, new JsonObject(), aad);
	}

	public SimpleEncryptedJWE encrypt(Enc enc, KeyEncryptionAlg alg) {
		return EncryptedJWEImpl.build(this, enc, alg);
	}

	public EncryptedJWE encrypt(Enc enc, KeyEncryptionAlg... algs) {
		var complexBuilder = new ComplexBuilder(payload, protectedHeader, new JsonObject(), "");
		return EncryptedJWEImpl.build(complexBuilder, enc, algs);
	}

	/// Integrated Encryption: the alg encrypts the payload directly, so there is no [Enc] and exactly one recipient.
	public SimpleEncryptedJWE encrypt(IntegratedEncryptionAlg alg) {
		var complexBuilder = new ComplexBuilder(payload, protectedHeader, new JsonObject(), "");
		return EncryptedJWEImpl.build(complexBuilder, alg);
	}

}
