package org.cryptomator.jose.builder;

/// An [EncryptedJWE] without AAD or an unprotected header and only a single Recipient.
public interface SimpleEncryptedJWE extends SingleRecipientEncryptedJWE {

	/// Serialize using [JWE Compact Serialization](https://www.rfc-editor.org/rfc/rfc7516#section-7.1)
	String toCompactSerialization();
}
