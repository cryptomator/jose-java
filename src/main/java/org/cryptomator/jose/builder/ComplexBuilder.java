package org.cryptomator.jose.builder;

import com.google.gson.JsonObject;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.IntegratedEncryptionAlg;
import org.cryptomator.jose.KeyEncryptionAlg;
import org.cryptomator.jose.Recipient;

import java.util.Arrays;

public record ComplexBuilder(String payload, JsonObject protectedHeader, JsonObject unprotectedHeader, String aad) implements Builder {

	public ComplexBuilder withProtectedHeader(JsonObject protectedHeader) {
		return new ComplexBuilder(payload, protectedHeader, unprotectedHeader, aad);
	}

	public ComplexBuilder withUnprotectedHeader(JsonObject unprotectedHeader) {
		return new ComplexBuilder(payload, protectedHeader, unprotectedHeader, aad);
	}

	public SingleRecipientEncryptedJWE encrypt(Enc enc, KeyEncryptionAlg alg) {
		return encrypt(enc, Recipient.withAlg(alg));
	}

	/// Key Encryption for a single recipient whose alg-generated and caller-supplied header parameters go into the per-recipient header.
	///
	/// @param enc The content encryption algorithm
	/// @param recipient The recipient, optionally carrying caller-supplied header parameters such as `kid`
	/// @return The encrypted JWE, serializable as Flattened or General JSON Serialization
	/// @throws IllegalArgumentException if a header parameter is present in more than one header location
	public SingleRecipientEncryptedJWE encrypt(Enc enc, Recipient recipient) {
		return EncryptedJWEImpl.build(this, enc, recipient);
	}

	public EncryptedJWE encrypt(Enc enc, KeyEncryptionAlg... algs) {
		return encrypt(enc, Arrays.stream(algs).map(Recipient::withAlg).toArray(Recipient[]::new));
	}

	/// Key Encryption for multiple recipients, each with its own per-recipient header.
	///
	/// @param enc The content encryption algorithm
	/// @param recipients The recipients (at least one)
	/// @return The encrypted JWE, serializable as General JSON Serialization only
	/// @throws IllegalArgumentException if no recipient is given, or if a header parameter is present in more than one header location
	public EncryptedJWE encrypt(Enc enc, Recipient... recipients) {
		return EncryptedJWEImpl.build(this, enc, recipients);
	}

	/// Integrated Encryption: the alg encrypts the payload directly, so there is no [Enc] and exactly one recipient.
	public SingleRecipientEncryptedJWE encrypt(IntegratedEncryptionAlg alg) {
		return EncryptedJWEImpl.build(this, alg);
	}

}
