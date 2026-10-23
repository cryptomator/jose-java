package org.cryptomator.jose.jwe;

import com.google.gson.JsonObject;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.IntegratedEncryptionAlg;
import org.cryptomator.jose.KeyEncryptionAlg;
import org.cryptomator.jose.Recipient;

import java.util.Arrays;

public record SimpleJWEBuilder(String payload, JsonObject protectedHeader) implements JWEBuilder {

	@Override
	public String toString() {
		return "SimpleJWEBuilder[payload=<redacted>, protectedHeader=" + protectedHeader + "]"; // keep the plaintext out of logs and debugger views
	}

	/// Sets the JWE Protected Header. "Protected" means integrity-protected: its parameters are authenticated but transmitted in cleartext, so they must not contain secrets.
	///
	/// @param protectedHeader Header parameters replacing the current ones (`alg` and `enc` are added when encrypting)
	/// @return A copy of this builder with the given protected header
	public SimpleJWEBuilder withProtectedHeader(JsonObject protectedHeader) {
		return new SimpleJWEBuilder(payload, protectedHeader);
	}

	/// Sets the JWE Shared Unprotected Header, whose parameters are neither encrypted nor integrity-protected. Only available in the JSON serializations.
	///
	/// @param unprotectedHeader Header parameters replacing the current ones
	/// @return A builder for the JSON serializations with the given shared unprotected header
	public ComplexJWEBuilder withUnprotectedHeader(JsonObject unprotectedHeader) {
		return new ComplexJWEBuilder(payload, protectedHeader, unprotectedHeader, "");
	}

	/// Sets the JWE AAD, which is integrity-protected but transmitted in cleartext. Only available in the JSON serializations.
	///
	/// @param aad The additional authenticated data as base64url string
	/// @return A builder for the JSON serializations with the given AAD
	public ComplexJWEBuilder withAad(String aad) {
		return new ComplexJWEBuilder(payload, protectedHeader, new JsonObject(), aad);
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
		var complexBuilder = new ComplexJWEBuilder(payload, protectedHeader, new JsonObject(), "");
		return EncryptedJWEImpl.build(complexBuilder, enc, recipients);
	}

	/// Integrated Encryption: the alg encrypts the payload directly, so there is no [Enc] and exactly one recipient.
	public SimpleEncryptedJWE encrypt(IntegratedEncryptionAlg alg) {
		var complexBuilder = new ComplexJWEBuilder(payload, protectedHeader, new JsonObject(), "");
		return EncryptedJWEImpl.build(complexBuilder, alg);
	}

}
