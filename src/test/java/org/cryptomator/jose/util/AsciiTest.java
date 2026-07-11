package org.cryptomator.jose.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

class AsciiTest {

	@Test
	@DisplayName("strictBytes encodes an ASCII string")
	void testAscii() {
		var input = "eyJmb28iOiJiYXIifQ.QUFB"; // base64url + separator, as used for the JWE AAD
		Assertions.assertArrayEquals(input.getBytes(StandardCharsets.US_ASCII), Ascii.strictBytes(input));
	}

	@Test
	@DisplayName("strictBytes rejects a non-ASCII string instead of substituting '?'")
	void testNonAscii() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> Ascii.strictBytes("café"));
	}
}
