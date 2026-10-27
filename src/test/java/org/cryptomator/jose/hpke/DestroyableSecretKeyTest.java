package org.cryptomator.jose.hpke;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

class DestroyableSecretKeyTest {

	@Test
	@DisplayName("the key owns a copy and hands out copies")
	void testCopies() {
		var bytes = new byte[]{1, 2, 3};
		var key = new DestroyableSecretKey(bytes, "Generic");
		bytes[0] = 9;
		var encoded = key.getEncoded();
		Assertions.assertArrayEquals(new byte[]{1, 2, 3}, encoded);
		encoded[1] = 9;
		Assertions.assertArrayEquals(new byte[]{1, 2, 3}, key.getEncoded());
		Assertions.assertEquals("Generic", key.getAlgorithm());
		Assertions.assertEquals("RAW", key.getFormat());
	}

	@Test
	@DisplayName("the range constructor copies only the given slice and validates its bounds")
	void testRangeConstructor() {
		var buffer = new byte[]{0, 1, 2, 3, 4};
		Assertions.assertArrayEquals(new byte[]{1, 2, 3}, new DestroyableSecretKey(buffer, 1, 3, "Generic").getEncoded());
		Assertions.assertArrayEquals(new byte[0], new DestroyableSecretKey(buffer, 5, 0, "Generic").getEncoded());
		Assertions.assertThrows(IllegalArgumentException.class, () -> new DestroyableSecretKey(buffer, 3, 3, "Generic"));
		Assertions.assertThrows(IllegalArgumentException.class, () -> new DestroyableSecretKey(buffer, -1, 1, "Generic"));
		Assertions.assertThrows(IllegalArgumentException.class, () -> new DestroyableSecretKey(buffer, 0, -1, "Generic"));
	}

	@Test
	@DisplayName("destroy wipes the key and blocks further access")
	void testDestroy() {
		var key = new DestroyableSecretKey(new byte[]{1, 2, 3}, "Generic");
		Assertions.assertFalse(key.isDestroyed());
		key.destroy();
		Assertions.assertTrue(key.isDestroyed());
		Assertions.assertThrows(IllegalStateException.class, key::getEncoded);
		Assertions.assertDoesNotThrow(key::destroy);
	}

	@Test
	@DisplayName("copyOf turns an unwipeable SecretKeySpec into a wipeable key with the same material")
	void testCopyOf() {
		var spec = new SecretKeySpec(new byte[]{4, 5, 6}, "AES");
		var key = DestroyableSecretKey.copyOf(spec);
		Assertions.assertArrayEquals(spec.getEncoded(), key.getEncoded());
		Assertions.assertEquals("AES", key.getAlgorithm());
		Assertions.assertThrows(javax.security.auth.DestroyFailedException.class, spec::destroy); // documents why the copy exists
		key.destroy();
		Assertions.assertTrue(key.isDestroyed());
	}

	@Test
	@DisplayName("toString never reveals key bytes")
	void testToString() {
		var key = new DestroyableSecretKey(new byte[]{1, 2, 3}, "Generic");
		Assertions.assertFalse(key.toString().contains("1, 2, 3"));
		Assertions.assertTrue(Arrays.asList(key.toString().split("\\W+")).contains("3"), "length may be shown");
	}

}
