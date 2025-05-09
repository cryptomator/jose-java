package org.cryptomator.jose.builder;

public interface EncryptedJWE {

	/// Serialize using [General JWE JSON Serialization](https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1)
	String toJsonSerialization();
}
