package org.cryptomator.jose;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AadEncodingTest {

	private static final char[] PASSWORD = "secret".toCharArray();

	@Test
	@DisplayName("encrypting with a non-ASCII AAD fails fast instead of silently mangling it")
	void testNonAsciiAadRejected() {
		var builder = JWE.build("payload").withAad("café"); // not base64url; contains a non-ASCII char
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.encrypt(Enc.A256GCM, Alg.pbes2(PASSWORD, 10)));
	}

	@Test
	@DisplayName("encrypting with a base64url (ASCII) AAD round-trips")
	void testAsciiAadRoundTrip() throws JoseException {
		var encrypted = JWE.build("payload").withAad("eyJmb28iOiJiYXIifQ").encrypt(Enc.A256GCM, Alg.pbes2(PASSWORD, 10)).toJsonSerialization();
		var decrypted = JWE.parse(encrypted).decrypt(Alg.pbes2(PASSWORD));
		Assertions.assertEquals("payload", decrypted.payload());
		Assertions.assertEquals("eyJmb28iOiJiYXIifQ", decrypted.aad());
	}
}
