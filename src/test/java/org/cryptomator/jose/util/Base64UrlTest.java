package org.cryptomator.jose.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Base64;

class Base64UrlTest {

	@Test
	@DisplayName("canonical unpadded base64url round-trips, including the empty string")
	void testRoundTrip() {
		for (int len = 0; len < 8; len++) {
			var bytes = new byte[len];
			for (int i = 0; i < len; i++) {
				bytes[i] = (byte) (0xF0 + i); // exercises '-' and '_'
			}
			var encoded = Base64Url.encode(bytes);
			Assertions.assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes), encoded);
			Assertions.assertArrayEquals(bytes, Base64Url.decode(encoded));
		}
	}

	@ParameterizedTest
	@ValueSource(strings = {
			"AA==", "AAA=", // padding
			"AB", "AAB", "_-B", // non-zero unused trailing bits: the JDK decodes these to the same bytes as "AA", "AAA", "_-A"
			"A", "AAAAA", // impossible lengths
			"AA+A", "AA/A", // standard alphabet
			"AA AA", "AA\nAA", "AA.AA", // whitespace and separators
	})
	@DisplayName("padding, non-canonical, mis-sized and non-alphabet input is rejected")
	void testRejectsNonCanonical(String encoded) {
		Assertions.assertThrows(IllegalArgumentException.class, () -> Base64Url.decode(encoded));
	}

	@Test
	@DisplayName("the JDK decoder would have accepted the padded and non-canonical variants")
	void testJdkIsLenient() {
		// documents why the strict decoder exists
		Assertions.assertArrayEquals(new byte[1], Base64.getUrlDecoder().decode("AA=="));
		Assertions.assertArrayEquals(new byte[1], Base64.getUrlDecoder().decode("AB"));
	}

}
