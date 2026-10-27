package org.cryptomator.jose;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AadEncodingTest {

	private static final char[] PASSWORD = "secret".toCharArray();

	@Test
	@DisplayName("a non-base64url AAD is refused by the builder instead of being silently mangled")
	void testNonBase64urlAadRejected() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> JWE.build("payload").withAad("café")); // non-ASCII
		Assertions.assertThrows(IllegalArgumentException.class, () -> JWE.build("payload").withAad("hello world")); // ASCII, but not base64url
		Assertions.assertThrows(IllegalArgumentException.class, () -> JWE.build("payload").withAad("YWFk=")); // padded
		Assertions.assertDoesNotThrow(() -> JWE.build("payload").withAad(""));
	}

	@Test
	@DisplayName("encrypting with a base64url (ASCII) AAD round-trips")
	void testAsciiAadRoundTrip() throws JoseException {
		var encrypted = JWE.build("payload").withAad("eyJmb28iOiJiYXIifQ").encrypt(Enc.A256GCM, Alg.pbes2(PASSWORD, 1000)).toJsonSerialization();
		var decrypted = JWE.parse(encrypted).decrypt(Alg.pbes2(PASSWORD));
		Assertions.assertEquals("payload", decrypted.payload());
		Assertions.assertEquals("eyJmb28iOiJiYXIifQ", decrypted.aad());
	}
}
