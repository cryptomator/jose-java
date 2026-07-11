package org.cryptomator.jose.builder;

import com.google.gson.JsonObject;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.IntegratedEncryptionAlg;
import org.cryptomator.jose.KeyEncryptionAlg;

public record ComplexBuilder(String payload, JsonObject protectedHeader, JsonObject unprotectedHeader, String aad) implements Builder {

	public ComplexBuilder withProtectedHeader(JsonObject protectedHeader) {
		return new ComplexBuilder(payload, protectedHeader, unprotectedHeader, aad);
	}

	public ComplexBuilder withUnprotectedHeader(JsonObject unprotectedHeader) {
		return new ComplexBuilder(payload, protectedHeader, unprotectedHeader, aad);
	}

	public SingleRecipientEncryptedJWE encrypt(Enc enc, KeyEncryptionAlg alg) {
		return EncryptedJWEImpl.build(this, enc, alg);
	}

	public EncryptedJWE encrypt(Enc enc, KeyEncryptionAlg... algs) {
		return EncryptedJWEImpl.build(this, enc, algs);
	}

	/// Integrated Encryption: the alg encrypts the payload directly, so there is no [Enc] and exactly one recipient.
	public SingleRecipientEncryptedJWE encrypt(IntegratedEncryptionAlg alg) {
		return EncryptedJWEImpl.build(this, alg);
	}

}
