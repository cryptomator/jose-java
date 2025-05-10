package org.cryptomator.jose;

import org.cryptomator.jose.alg.Pbes2Alg;
import org.cryptomator.jose.builder.SimpleEncryptedJWE;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class JWEIntegrationTest {

	@Nested
	@DisplayName("serialize and parse")
	class SerializeAndParse {

		private SimpleEncryptedJWE encryptedJWE;

		@BeforeEach
		public void setup() {
			encryptedJWE = JWE.build("payload").encrypt(Enc.A256GCM, Alg.pbes2("secret".toCharArray(), 10));
		}

		@Test
		@DisplayName("general JSON serialization")
		public void testGeneralJson() throws JoseParseException {
			var json = encryptedJWE.toJsonSerialization();
			var parsed = JWE.parse(json);
			Assertions.assertEquals("A256GCM", parsed.parsedProtectedHeader().get("enc").getAsString());
		}

		@Test
		@DisplayName("flattened JSON serialization")
		public void testFlattenedJson() throws JoseParseException {
			var json = encryptedJWE.toFlattenedJsonSerialization();
			var parsed = JWE.parse(json);
			Assertions.assertEquals("A256GCM", parsed.parsedProtectedHeader().get("enc").getAsString());
		}

		@Test
		@DisplayName("compact serialization")
		public void testCompact() throws JoseParseException {
			var json = encryptedJWE.toCompactSerialization();
			var parsed = JWE.parse(json);
			Assertions.assertEquals("A256GCM", parsed.parsedProtectedHeader().get("enc").getAsString());
		}
	}

	@Nested
	@DisplayName("encrypt and decrypt")
	class EncryptAndDecrypt {

		@Test
		@DisplayName("PBES2-HS512+A256KW")
		public void testPBES2HS512A256KW() throws JoseException {
			var encrypted = JWE.build("payload").encrypt(Enc.A256GCM, Alg.pbes2("secret".toCharArray(), 10)).toJsonSerialization();
			var decrypted = JWE.parse(encrypted).decrypt(Alg.pbes2("secret".toCharArray()));
			Assertions.assertEquals("payload", decrypted.payload());
		}

		@Test
		@DisplayName("PBES2-HS256+A128KW")
		public void testPBES2HS256A128KW() throws JoseException {
			var alg = new Pbes2Alg(Pbes2Alg.Type.PBES2_HS256_A128KW, "secret".toCharArray(), 10);
			var encrypted = JWE.build("payload").encrypt(Enc.A256GCM, alg).toJsonSerialization();
			var decrypted = JWE.parse(encrypted).decrypt(alg);
			Assertions.assertEquals("payload", decrypted.payload());
		}

	}

}