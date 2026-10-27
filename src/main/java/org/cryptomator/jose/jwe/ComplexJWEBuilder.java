package org.cryptomator.jose.jwe;

import com.google.gson.JsonObject;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.IntegratedEncryptionAlg;
import org.cryptomator.jose.KeyEncryptionAlg;
import org.cryptomator.jose.Recipient;
import org.cryptomator.jose.util.Base64Url;

import java.util.Arrays;

public record ComplexJWEBuilder(String payload, JsonObject protectedHeader, JsonObject unprotectedHeader, String aad) implements JWEBuilder {

	/// @throws IllegalArgumentException if `aad` is not canonical base64url ([RFC 7516, Section 7.2.1](https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1): the `aad` member is BASE64URL(JWE AAD))
	public ComplexJWEBuilder {
		try {
			Base64Url.decode(aad); // the empty string decodes fine and means "no AAD"
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("aad must be base64url", e);
		}
	}

	@Override
	public String toString() {
		return "ComplexJWEBuilder[payload=<redacted>, protectedHeader=" + protectedHeader + ", unprotectedHeader=" + unprotectedHeader + ", aad=" + aad + "]"; // keep the plaintext out of logs and debugger views
	}

	/// Sets the JWE Protected Header. "Protected" means integrity-protected: its parameters are authenticated but transmitted in cleartext, so they must not contain secrets.
	///
	/// @param protectedHeader Header parameters replacing the current ones (`alg` and `enc` are added when encrypting)
	/// @return A copy of this builder with the given protected header
	public ComplexJWEBuilder withProtectedHeader(JsonObject protectedHeader) {
		return new ComplexJWEBuilder(payload, protectedHeader, unprotectedHeader, aad);
	}

	/// Sets the JWE Shared Unprotected Header, whose parameters are neither encrypted nor integrity-protected.
	///
	/// @param unprotectedHeader Header parameters replacing the current ones
	/// @return A copy of this builder with the given shared unprotected header
	public ComplexJWEBuilder withUnprotectedHeader(JsonObject unprotectedHeader) {
		return new ComplexJWEBuilder(payload, protectedHeader, unprotectedHeader, aad);
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
