package org.cryptomator.jose.alg;

import com.google.gson.JsonObject;
import org.cryptomator.jose.Alg;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.JWE;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.JoseException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Base64;

class Pbes2AlgTest {

	/// test vector from [RFC 7517, Appendix C](https://www.rfc-editor.org/rfc/rfc7517#appendix-C): a JWK encrypted with PBES2-HS256+A128KW
	@Nested
	@DisplayName("RFC 7517 Appendix C")
	class Rfc7517AppendixC {

		private static final char[] PASSWORD = "Thus from my lips, by yours, my sin is purged.".toCharArray();
		private static final String P2S = "2WCTcJZ1Rvd_CJuJripQ1w";
		private static final int P2C = 4096;
		private static final byte[] ENCRYPTED_KEY = Base64.getUrlDecoder().decode("TrqXOwuNUfDV9VPTNbyGvEJ9JMjefAVn-TR1uIxR9p6hsRQh9Tk7BA");
		private static final byte[] CEK = {111, 27, 25, 52, 66, 29, 20, 78, 92, (byte) 176, 56, (byte) 240, 65, (byte) 208, 82, 112, (byte) 161, (byte) 131, 36, 55, (byte) 202, (byte) 236, (byte) 185, (byte) 172, (byte) 129, 23, (byte) 153, (byte) 194, (byte) 195, 48, (byte) 253, (byte) 182};

		private final Pbes2Alg alg = new Pbes2Alg(Pbes2Alg.Type.PBES2_HS256_A128KW, PASSWORD, 1000);

		private static JsonObject header(String alg, String p2s, Number p2c) {
			var header = new JsonObject();
			header.addProperty("alg", alg);
			if (p2s != null) {
				header.addProperty("p2s", p2s);
			}
			if (p2c != null) {
				header.addProperty("p2c", p2c);
			}
			return header;
		}

		@Test
		@DisplayName("unwraps the CEK")
		void testDecryptKey() throws JoseDecryptException {
			Assertions.assertArrayEquals(CEK, alg.decryptKey(header("PBES2-HS256+A128KW", P2S, P2C), ENCRYPTED_KEY));
		}

		@Test
		@DisplayName("wrong password fails the key unwrap integrity check")
		void testWrongPassword() {
			var wrongAlg = new Pbes2Alg(Pbes2Alg.Type.PBES2_HS256_A128KW, "wrong".toCharArray(), 1000);
			Assertions.assertThrows(DecryptKeyException.class, () -> wrongAlg.decryptKey(header("PBES2-HS256+A128KW", P2S, P2C), ENCRYPTED_KEY));
		}

		@Test
		@DisplayName("alg mismatch is a key decryption failure")
		void testAlgMismatch() {
			Assertions.assertThrows(DecryptKeyException.class, () -> alg.decryptKey(header("PBES2-HS512+A256KW", P2S, P2C), ENCRYPTED_KEY));
		}

		@Test
		@DisplayName("missing p2s is a key decryption failure")
		void testMissingP2s() {
			Assertions.assertThrows(DecryptKeyException.class, () -> alg.decryptKey(header("PBES2-HS256+A128KW", null, P2C), ENCRYPTED_KEY));
		}

		@Test
		@DisplayName("p2s shorter than 8 bytes is rejected")
		void testShortP2s() {
			Assertions.assertThrows(DecryptKeyException.class, () -> alg.decryptKey(header("PBES2-HS256+A128KW", "c2FsdA", P2C), ENCRYPTED_KEY)); // "salt"
		}

		@Test
		@DisplayName("missing p2c is a key decryption failure")
		void testMissingP2c() {
			Assertions.assertThrows(DecryptKeyException.class, () -> alg.decryptKey(header("PBES2-HS256+A128KW", P2S, null), ENCRYPTED_KEY));
		}

		@Test
		@DisplayName("p2c above the cap is rejected before deriving the key")
		void testExcessiveP2c() {
			Assertions.assertThrows(DecryptKeyException.class, () -> alg.decryptKey(header("PBES2-HS256+A128KW", P2S, 1_000_001), ENCRYPTED_KEY));
		}

		@Test
		@DisplayName("non-integer p2c is rejected")
		void testFractionalP2c() {
			Assertions.assertThrows(DecryptKeyException.class, () -> alg.decryptKey(header("PBES2-HS256+A128KW", P2S, 4096.5), ENCRYPTED_KEY));
		}

	}

	@Test
	@DisplayName("a malformed PBES2 recipient is skipped in favor of a later valid one")
	void testMalformedRecipientIsSkipped() throws JoseException {
		var alg = Alg.pbes2("secret".toCharArray(), 1000);
		var jwe = com.google.gson.JsonParser.parseString(JWE.build("payload").encrypt(Enc.A256GCM, alg, alg).toJsonSerialization()).getAsJsonObject();
		jwe.getAsJsonArray("recipients").get(0).getAsJsonObject().getAsJsonObject("header").remove("p2s");

		Assertions.assertEquals("payload", JWE.parse(jwe.toString()).decrypt(Alg.pbes2("secret".toCharArray())).payload());
	}


	@Nested
	@DisplayName("iteration count")
	class IterationCount {

		@Test
		@DisplayName("the single-arg factory encrypts with the default iteration count and decrypts")
		void testDefaultP2c() throws JoseException {
			var alg = Alg.pbes2("secret".toCharArray());
			var parsed = JWE.parse(JWE.build("payload").encrypt(Enc.A256GCM, alg).toCompactSerialization());

			Assertions.assertEquals(Pbes2Alg.DEFAULT_P2C, parsed.parsedProtectedHeader().get("p2c").getAsInt());
			Assertions.assertEquals("payload", parsed.decrypt(alg).payload());
		}

		@Test
		@DisplayName("p2c below MIN_P2C is rejected on construction")
		void testP2cTooSmall() {
			Assertions.assertThrows(IllegalArgumentException.class, () -> Alg.pbes2("secret".toCharArray(), Pbes2Alg.MIN_P2C - 1));
		}

		@Test
		@DisplayName("p2c above MAX_P2C is rejected on construction")
		void testP2cTooLarge() {
			Assertions.assertThrows(IllegalArgumentException.class, () -> Alg.pbes2("secret".toCharArray(), Pbes2Alg.MAX_P2C + 1));
		}

		@Test
		@DisplayName("p2c of exactly MAX_P2C round-trips")
		void testP2cAtMax() throws JoseException {
			var alg = Alg.pbes2("secret".toCharArray(), Pbes2Alg.MAX_P2C);
			var jwe = JWE.build("payload").encrypt(Enc.A256GCM, alg).toCompactSerialization();

			Assertions.assertEquals("payload", JWE.parse(jwe).decrypt(alg).payload());
		}

	}

}
