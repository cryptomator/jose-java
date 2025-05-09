package org.cryptomator.jose.builder;

/// An [EncryptedJWE] with a single recipient.
public interface SingleRecipientEncryptedJWE extends EncryptedJWE {

	/// Serialize using [Flattened JWE JSON Serialization](https://www.rfc-editor.org/rfc/rfc7516#section-7.2.2)
	String toFlattenedJsonSerialization();

}
