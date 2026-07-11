package org.cryptomator.jose;

import org.cryptomator.jose.alg.EcdhEsAlg;
import org.cryptomator.jose.alg.HPKEKeyEncryptionAlg;
import org.cryptomator.jose.alg.Pbes2Alg;
import org.cryptomator.jose.builder.SimpleEncryptedJWE;
import org.cryptomator.jose.hpke.HPKE;
import org.cryptomator.jose.hpke.XwingProvider;
import org.cryptomator.jose.util.Curve;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.stream.Stream;

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

		@ParameterizedTest
		@MethodSource
		public void testEncryptAndDecrypt(EncryptionAlg encAlg, DecryptionAlg decAlg) throws JoseException {
			var encrypted = JWE.build("payload").encrypt(Enc.A256GCM, encAlg).toJsonSerialization();
			var decrypted = JWE.parse(encrypted).decrypt(decAlg);
			Assertions.assertEquals("payload", decrypted.payload());
		}

		static Stream<Arguments> testEncryptAndDecrypt() throws GeneralSecurityException {
			var ecKeyGen = KeyPairGenerator.getInstance("EC");
			ecKeyGen.initialize(new ECGenParameterSpec("secp256r1"));
			var p256KeyPair = ecKeyGen.generateKeyPair();
			ecKeyGen.initialize(new ECGenParameterSpec("secp384r1"));
			var p384KeyPair = ecKeyGen.generateKeyPair();
			ecKeyGen.initialize(new ECGenParameterSpec("secp521r1"));
			var p521KeyPair = ecKeyGen.generateKeyPair();
			var xwingKeyGen = KeyPairGenerator.getInstance("X-Wing", XwingProvider.INSTANCE);
			var xwingKeyPair = xwingKeyGen.generateKeyPair();

			var hpke0Ke = new HPKEKeyEncryptionAlg(HPKE.hpke0(), p256KeyPair.getPublic(), p256KeyPair.getPrivate());
			var hpke1Ke = new HPKEKeyEncryptionAlg(HPKE.hpke1(), p384KeyPair.getPublic(), p384KeyPair.getPrivate());
			var hpke2Ke = new HPKEKeyEncryptionAlg(HPKE.hpke2(), p521KeyPair.getPublic(), p521KeyPair.getPrivate());
			var hpke9Ke = new HPKEKeyEncryptionAlg(HPKE.hpke9(), xwingKeyPair.getPublic(), xwingKeyPair.getPrivate());
			var ecdhEs = new EcdhEsAlg(EcdhEsAlg.Type.ECDH_ES_A256KW, Curve.P384, (ECPublicKey) p384KeyPair.getPublic(), (ECPrivateKey) p384KeyPair.getPrivate());
			var pbes2Hs256A128Kw = new Pbes2Alg(Pbes2Alg.Type.PBES2_HS256_A128KW, "secret".toCharArray(), 10);
			var pbes2Hs512A256Kw = new Pbes2Alg(Pbes2Alg.Type.PBES2_HS512_A256KW, "secret".toCharArray(), 10);

			return Stream.of(
					Arguments.argumentSet("HPKE-0-KE", hpke0Ke, hpke0Ke),
					Arguments.argumentSet("HPKE-1-KE", hpke1Ke, hpke1Ke),
					Arguments.argumentSet("HPKE-2-KE", hpke2Ke, hpke2Ke),
					Arguments.argumentSet("HPKE-9-KE", hpke9Ke, hpke9Ke),
					Arguments.argumentSet("ECDH-ES+A256KW", ecdhEs, ecdhEs),
					Arguments.argumentSet("PBES2_HS256_A128KW", pbes2Hs256A128Kw, pbes2Hs256A128Kw),
					Arguments.argumentSet("PBES2_HS512_A256KW", pbes2Hs512A256Kw, pbes2Hs512A256Kw)
			);
		}

	}

}