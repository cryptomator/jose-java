package org.cryptomator.jose;

import com.google.gson.JsonArray;
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

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.stream.Stream;

class JWEIntegrationTest {

	@Nested
	@DisplayName("malformed content is rejected at decrypt")
	class MalformedContent {

		private JsonObject validJwe() {
			// a valid PBES2 JWE with a 12-byte iv and 16-byte tag
			var jwe = JWE.build("payload").encrypt(Enc.A256GCM, Alg.pbes2("secret".toCharArray(), 10)).toJsonSerialization();
			return JsonParser.parseString(jwe).getAsJsonObject();
		}

		@Test
		@DisplayName("a Key Encryption token with a stripped iv fails with a checked exception")
		public void testStrippedIv() {
			var json = validJwe();
			json.remove("iv");
			var parsed = Assertions.assertDoesNotThrow(() -> JWE.parse(json.toString()));
			Assertions.assertThrows(JoseDecryptException.class, () -> parsed.decrypt(Alg.pbes2("secret".toCharArray())));
		}

		@Test
		@DisplayName("a Key Encryption token with a stripped tag fails with a checked exception")
		public void testStrippedTag() {
			var json = validJwe();
			json.remove("tag");
			var parsed = Assertions.assertDoesNotThrow(() -> JWE.parse(json.toString()));
			Assertions.assertThrows(JoseDecryptException.class, () -> parsed.decrypt(Alg.pbes2("secret".toCharArray())));
		}

		@Test
		@DisplayName("an unsupported enc value fails with a checked exception")
		public void testUnsupportedEnc() {
			var json = validJwe();
			var base64url = Base64.getUrlDecoder();
			var protectedJson = JsonParser.parseString(new String(base64url.decode(json.get("protected").getAsString()), StandardCharsets.UTF_8)).getAsJsonObject();
			protectedJson.addProperty("enc", "A192GCM"); // not supported by this library
			json.addProperty("protected", Base64.getUrlEncoder().withoutPadding().encodeToString(protectedJson.toString().getBytes(StandardCharsets.UTF_8)));
			var parsed = Assertions.assertDoesNotThrow(() -> JWE.parse(json.toString()));
			Assertions.assertThrows(JoseDecryptException.class, () -> parsed.decrypt(Alg.pbes2("secret".toCharArray())));
		}
	}

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

			var json = JsonParser.parseString(JWE.build("payload").encrypt(Alg.hpke9(keyPair.getPublic())).toJsonSerialization()).getAsJsonObject();
			// prepend a malformed recipient that trips the Integrated Encryption enc/ek guard:
			var validRecipient = json.getAsJsonArray("recipients").get(0).getAsJsonObject();
			var malformedRecipient = validRecipient.deepCopy();
			var injectedHeader = new JsonObject();
			injectedHeader.addProperty("enc", "A128GCM");
			malformedRecipient.add("header", injectedHeader);
			var recipients = new JsonArray();
			recipients.add(malformedRecipient);
			recipients.add(validRecipient);
			json.add("recipients", recipients);

			var decrypted = JWE.parse(json.toString()).decrypt(Alg.hpke9(keyPair.getPrivate()));
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