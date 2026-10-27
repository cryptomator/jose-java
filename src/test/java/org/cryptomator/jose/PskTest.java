package org.cryptomator.jose;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;

class PskTest {

	private static final SecretKeySpec KEY = new SecretKeySpec(new byte[32], "Generic");

	@Test
	@DisplayName("key and id must be present and non-empty")
	void testValidation() {
		Assertions.assertThrows(NullPointerException.class, () -> new Psk(null, new byte[]{1}));
		Assertions.assertThrows(NullPointerException.class, () -> new Psk(KEY, null));
		Assertions.assertThrows(IllegalArgumentException.class, () -> new Psk(KEY, new byte[0]));
		Assertions.assertThrows(IllegalArgumentException.class, () -> new Psk(new SecretKeySpec(new byte[1], "Generic") {
			@Override
			public byte[] getEncoded() {
				return null;
			}
		}, new byte[]{1}));
		Assertions.assertDoesNotThrow(() -> new Psk(KEY, new byte[]{1}));
	}

	@Test
	@DisplayName("the id is copied in and out, the key stays the caller's")
	void testCopies() {
		var id = new byte[]{1, 2, 3};
		var psk = new Psk(KEY, id);
		id[0] = 9;
		Assertions.assertArrayEquals(new byte[]{1, 2, 3}, psk.id());
		psk.id()[0] = 9;
		Assertions.assertArrayEquals(new byte[]{1, 2, 3}, psk.id());
		Assertions.assertSame(KEY, psk.key());
	}

	@Test
	@DisplayName("equality is by key and id content; toString reveals neither")
	void testEqualsAndToString() {
		Assertions.assertEquals(new Psk(KEY, new byte[]{1}), new Psk(KEY, new byte[]{1}));
		Assertions.assertNotEquals(new Psk(KEY, new byte[]{1}), new Psk(KEY, new byte[]{2}));
		Assertions.assertEquals("Psk[key=<redacted>, id=1 bytes]", new Psk(KEY, new byte[]{1}).toString());
	}

}
