package org.cryptomator.jose;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.cryptomator.jose.alg.EcdhEsAlg;
import org.cryptomator.jose.alg.HPKEIntegratedAlg;
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

import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.stream.Stream;

@DisplayName("JWE: end-to-end round trips")
class JWEIT {

	@Nested
	@DisplayName("per-recipient headers")
	class PerRecipientHeaders {

		private final SymmetricKeyAlg kek = Alg.a256kw(new SecretKeySpec(new byte[32], "AES"));
		private KeyPair ecKeyPair;

		@BeforeEach
		void setup() throws GeneralSecurityException {
			var ecKeyGen = KeyPairGenerator.getInstance("EC");
			ecKeyGen.initialize(new ECGenParameterSpec("secp384r1"));
			ecKeyPair = ecKeyGen.generateKeyPair();
		}

		private static JsonObject json(String json) {
			return JsonParser.parseString(json).getAsJsonObject();
		}

		@Test
		@DisplayName("kid and private params are per recipient, visible before decryption, and returned with the decrypted header")
		void testTwoRecipientsWithHeaders() throws JoseException {
			var passwordRecipient = Recipient.withAlg(kek)
					.withClaim("kid", "org.example.password")
					.withClaim("org.example.argon2.salt", "c2FsdHNhbHRzYWx0")
					.withClaim("org.example.argon2.iterations", 3)
					.withClaim("org.example.argon2.committed", true);
			var recoveryRecipient = Recipient.withAlg(Alg.ecdhEs(ecKeyPair.getPublic())).withClaim("kid", "org.example.recovery");

			var jwe = JWE.build("payload").withProtectedHeader(json("{\"cty\":\"json\"}")).encrypt(Enc.A256GCM, passwordRecipient, recoveryRecipient).toJsonSerialization();
			var parsed = JWE.parse(jwe);

			// the protected header carries only shared params:
			Assertions.assertEquals(json("{\"cty\":\"json\",\"enc\":\"A256GCM\"}"), parsed.parsedProtectedHeader());
			// each recipient's header is readable up front:
			var headers = parsed.recipientHeaders();
			Assertions.assertEquals(2, headers.size());
			Assertions.assertEquals("A256KW", headers.get(0).get("alg").getAsString());
			Assertions.assertEquals("org.example.password", headers.get(0).get("kid").getAsString());
			Assertions.assertEquals(3, headers.get(0).get("org.example.argon2.iterations").getAsInt());
			Assertions.assertTrue(headers.get(0).get("org.example.argon2.committed").getAsBoolean());
			Assertions.assertEquals("ECDH-ES+A256KW", headers.get(1).get("alg").getAsString());
			Assertions.assertEquals("org.example.recovery", headers.get(1).get("kid").getAsString());
			Assertions.assertTrue(headers.get(1).has("epk"));
			// and either recipient decrypts, getting its own header back:
			var viaPassword = parsed.decrypt(kek);
			Assertions.assertEquals("payload", viaPassword.payload());
			Assertions.assertEquals("org.example.password", viaPassword.unprotectedHeader().get("kid").getAsString());
			var viaRecovery = parsed.decrypt(Alg.ecdhEs(ecKeyPair.getPrivate()));
			Assertions.assertEquals("payload", viaRecovery.payload());
			Assertions.assertEquals("org.example.recovery", viaRecovery.unprotectedHeader().get("kid").getAsString());
		}

	}

	@Nested
	@DisplayName("serialize and parse")
	class SerializeAndParse {

		private SimpleEncryptedJWE encryptedJWE;

		@BeforeEach
		public void setup() {
			encryptedJWE = JWE.build("payload").encrypt(Enc.A256GCM, Alg.pbes2("secret".toCharArray(), 1000));
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
	@DisplayName("integrated encryption: encrypt and decrypt")
	class IntegratedEncryptAndDecrypt {

		@ParameterizedTest
		@MethodSource("algs")
		@DisplayName("compact serialization round trip")
		public void testCompactRoundTrip(HPKEIntegratedAlg alg) throws JoseException {
			var encrypted = JWE.build("payload").encrypt(alg).toCompactSerialization();
			var decrypted = JWE.parse(encrypted).decrypt(alg);
			Assertions.assertEquals("payload", decrypted.payload());
		}

		@ParameterizedTest
		@MethodSource("algs")
		@DisplayName("general JSON serialization round trip")
		public void testJsonRoundTrip(HPKEIntegratedAlg alg) throws JoseException {
			var encrypted = JWE.build("payload").encrypt(alg).toJsonSerialization();
			var decrypted = JWE.parse(encrypted).decrypt(alg);
			Assertions.assertEquals("payload", decrypted.payload());
		}

		@ParameterizedTest
		@MethodSource("algs")
		@DisplayName("flattened JSON serialization with AAD round trip")
		public void testFlattenedWithAadRoundTrip(HPKEIntegratedAlg alg) throws JoseException {
			var encrypted = JWE.build("payload").withAad("eyJmb28iOiJiYXIifQ").encrypt(alg).toFlattenedJsonSerialization();
			var decrypted = JWE.parse(encrypted).decrypt(alg);
			Assertions.assertEquals("payload", decrypted.payload());
			Assertions.assertEquals("eyJmb28iOiJiYXIifQ", decrypted.aad());
		}

		@ParameterizedTest
		@MethodSource("algs")
		@DisplayName("no enc/ek/iv/tag on the wire")
		public void testWireShape(HPKEIntegratedAlg alg) throws JoseException {
			var encrypted = JWE.build("payload").encrypt(alg).toFlattenedJsonSerialization();
			var json = JsonParser.parseString(encrypted).getAsJsonObject();
			Assertions.assertFalse(json.has("iv"));
			Assertions.assertFalse(json.has("tag"));
			var protectedHeader = JWE.parse(encrypted).parsedProtectedHeader();
			Assertions.assertFalse(protectedHeader.has("enc"));
			Assertions.assertFalse(protectedHeader.has("ek"));
			Assertions.assertEquals(alg.name(), protectedHeader.get("alg").getAsString());
		}

		@Test
		@DisplayName("wrong key is skipped, matching key decrypts")
		public void testMultipleCandidateKeys() throws JoseException, GeneralSecurityException {
			var xwingKeyGen = KeyPairGenerator.getInstance("X-Wing", XwingProvider.INSTANCE);
			var rightKeyPair = xwingKeyGen.generateKeyPair();
			var wrongKeyPair = xwingKeyGen.generateKeyPair();

			var encrypted = JWE.build("payload").encrypt(Alg.hpke9(rightKeyPair.getPublic())).toCompactSerialization();
			var decrypted = JWE.parse(encrypted).decrypt(Alg.hpke9(wrongKeyPair.getPrivate()), Alg.hpke9(rightKeyPair.getPrivate()));
			Assertions.assertEquals("payload", decrypted.payload());
		}

		@Test
		@DisplayName("key encryption alg does not match integrated encryption token")
		public void testModeMismatch() throws GeneralSecurityException, JoseParseException {
			var xwingKeyGen = KeyPairGenerator.getInstance("X-Wing", XwingProvider.INSTANCE);
			var keyPair = xwingKeyGen.generateKeyPair();

			var encrypted = JWE.build("payload").encrypt(Alg.hpke9(keyPair.getPublic())).toCompactSerialization();
			var parsed = JWE.parse(encrypted);
			Assertions.assertThrows(JoseDecryptException.class, () -> parsed.decrypt(Alg.hpke9Ke(keyPair.getPrivate()))); // "HPKE-9-KE" does not match "HPKE-9"
		}

		@Test
		@DisplayName("a malformed leading recipient is skipped, a valid one decrypts")
		public void testSkipMalformedLeadingRecipient() throws GeneralSecurityException, JoseException {
			var xwingKeyGen = KeyPairGenerator.getInstance("X-Wing", XwingProvider.INSTANCE);
			var keyPair = xwingKeyGen.generateKeyPair();

			// Key Encryption, since Integrated Encryption is limited to exactly one recipient; two recipients keep alg/ek in the per-recipient headers
			var json = JsonParser.parseString(JWE.build("payload").encrypt(Enc.A256GCM, Alg.hpke9Ke(keyPair.getPublic()), Alg.hpke9Ke(keyPair.getPublic())).toJsonSerialization()).getAsJsonObject();
			// corrupt the leading recipient's encapsulation so that decapsulation fails and the loop moves on:
			var recipients = json.getAsJsonArray("recipients");
			recipients.get(0).getAsJsonObject().getAsJsonObject("header").addProperty("ek", "AAAA");

			var decrypted = JWE.parse(json.toString()).decrypt(Alg.hpke9Ke(keyPair.getPrivate()));
			Assertions.assertEquals("payload", decrypted.payload());
		}

		static Stream<Arguments> algs() throws GeneralSecurityException {
			var ecKeyGen = KeyPairGenerator.getInstance("EC");
			ecKeyGen.initialize(new ECGenParameterSpec("secp256r1"));
			var p256KeyPair = ecKeyGen.generateKeyPair();
			ecKeyGen.initialize(new ECGenParameterSpec("secp384r1"));
			var p384KeyPair = ecKeyGen.generateKeyPair();
			ecKeyGen.initialize(new ECGenParameterSpec("secp521r1"));
			var p521KeyPair = ecKeyGen.generateKeyPair();
			var xwingKeyGen = KeyPairGenerator.getInstance("X-Wing", XwingProvider.INSTANCE);
			var xwingKeyPair = xwingKeyGen.generateKeyPair();

			return Stream.of(
					Arguments.argumentSet("HPKE-0", new HPKEIntegratedAlg(HPKE.hpke0(), p256KeyPair.getPublic(), p256KeyPair.getPrivate())),
					Arguments.argumentSet("HPKE-1", new HPKEIntegratedAlg(HPKE.hpke1(), p384KeyPair.getPublic(), p384KeyPair.getPrivate())),
					Arguments.argumentSet("HPKE-2", new HPKEIntegratedAlg(HPKE.hpke2(), p521KeyPair.getPublic(), p521KeyPair.getPrivate())),
					Arguments.argumentSet("HPKE-9", new HPKEIntegratedAlg(HPKE.hpke9(), xwingKeyPair.getPublic(), xwingKeyPair.getPrivate()))
			);
		}

	}

	@Nested
	@DisplayName("encrypt and decrypt")
	class EncryptAndDecrypt {

		@ParameterizedTest
		@MethodSource
		public void testEncryptAndDecrypt(KeyEncryptionAlg encAlg, DecryptionAlg decAlg) throws JoseException {
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
			var pbes2Hs256A128Kw = new Pbes2Alg(Pbes2Alg.Type.PBES2_HS256_A128KW, "secret".toCharArray(), 1000);
			var pbes2Hs512A256Kw = new Pbes2Alg(Pbes2Alg.Type.PBES2_HS512_A256KW, "secret".toCharArray(), 1000);
			var a256kw = Alg.a256kw(new SecretKeySpec(new byte[32], "AES"));

			return Stream.of(
					Arguments.argumentSet("A256KW", a256kw, a256kw),
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