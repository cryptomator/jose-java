package org.cryptomator.jose.builder;

import com.google.gson.JsonObject;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.IntegratedEncryptionAlg;
import org.cryptomator.jose.KeyEncryptionAlg;
import org.cryptomator.jose.Recipient;

import java.util.Arrays;

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
		return encrypt(enc, Recipient.withAlg(alg));
	}

	/// Key Encryption for a single recipient. All header parameters (including the recipient's) go into the protected header, so this is the only
	/// path to a JWE that supports the compact serialization.
	///
	/// @param enc The content encryption algorithm
	/// @param recipient The recipient, optionally carrying caller-supplied header parameters such as `kid`
	/// @return The encrypted JWE, serializable in all three serializations
	/// @throws IllegalArgumentException if a header parameter is present in more than one of: the protected header, the recipient's header, the alg-generated header
	public SimpleEncryptedJWE encrypt(Enc enc, Recipient recipient) {
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
		var complexBuilder = new ComplexBuilder(payload, protectedHeader, new JsonObject(), "");
		return EncryptedJWEImpl.build(complexBuilder, enc, recipients);
	}

	/// Integrated Encryption: the alg encrypts the payload directly, so there is no [Enc] and exactly one recipient.
	public SimpleEncryptedJWE encrypt(IntegratedEncryptionAlg alg) {
		var complexBuilder = new ComplexBuilder(payload, protectedHeader, new JsonObject(), "");
		return EncryptedJWEImpl.build(complexBuilder, alg);
	}

}
