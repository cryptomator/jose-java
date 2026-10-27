package org.cryptomator.jose.jwe;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.cryptomator.jose.Alg;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.JWE;
import org.cryptomator.jose.SymmetricKeyAlg;
import org.cryptomator.jose.Recipient;
import org.cryptomator.jose.hpke.XwingProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import org.cryptomator.jose.JoseException;
import java.util.List;

/// Header assembly rules of the encrypt-side builders ([SimpleJWEBuilder], [ComplexJWEBuilder], [EncryptedJWEImpl]).
class JWEBuilderTest {

	private final SymmetricKeyAlg kek = Alg.a256kw(new SecretKeySpec(new byte[32], "AES"));

	private static JsonObject json(String json) {
		return JsonParser.parseString(json).getAsJsonObject();
	}

	// the decoded protected header of a compact serialization
	private static JsonObject protectedHeaderOf(String compact) {
		var encoded = compact.substring(0, compact.indexOf('.'));
		return json(new String(Base64.getUrlDecoder().decode(encoded), StandardCharsets.UTF_8));
	}

	@Test
	@DisplayName("builders' toString does not reveal the payload")
	void testToStringRedactsPayload() {
		var simple = JWE.build("payload");
		Assertions.assertTrue(simple.toString().contains("payload=<redacted>"));
		Assertions.assertTrue(simple.withAad("YWFk").toString().contains("payload=<redacted>"));
	}

	@Nested
	@DisplayName("per-recipient header placement")
	class Placement {

		@Test
		@DisplayName("single recipient, compact serialization: recipient params are folded into the protected header")
		void testCompactFoldsIntoProtectedHeader() {
			var jwe = JWE.build("payload").encrypt(Enc.A128GCM, Recipient.withAlg(kek).withClaim("kid", "org.example.kid")).toCompactSerialization();
			Assertions.assertEquals(json("{\"enc\":\"A128GCM\",\"alg\":\"A256KW\",\"kid\":\"org.example.kid\"}"), protectedHeaderOf(jwe));
		}

		@Test
		@DisplayName("single recipient with AAD: recipient params stay in the per-recipient header")
		void testFlattenedKeepsPerRecipientHeader() {
			var jwe = JWE.build("payload").withAad("YWFk").encrypt(Enc.A128GCM, Recipient.withAlg(kek).withClaim("kid", "org.example.kid")).toFlattenedJsonSerialization();
			var json = JsonParser.parseString(jwe).getAsJsonObject();
			Assertions.assertEquals(json("{\"alg\":\"A256KW\",\"kid\":\"org.example.kid\"}"), json.getAsJsonObject("header"));
			Assertions.assertEquals(json("{\"enc\":\"A128GCM\"}"), json(new String(Base64.getUrlDecoder().decode(json.get("protected").getAsString()), StandardCharsets.UTF_8)));
		}

		@Test
		@DisplayName("multiple recipients: each gets its own params, shared ones stay shared")
		void testGeneralKeepsPerRecipientHeaders() {
			var jwe = JWE.build("payload").withUnprotectedHeader(json("{\"shared\":true}"))
					.encrypt(Enc.A256GCM, Recipient.withAlg(kek).withClaim("kid", "a"), Recipient.withAlg(kek).withClaim("kid", "b"))
					.toJsonSerialization();
			var json = JsonParser.parseString(jwe).getAsJsonObject();
			var recipients = json.getAsJsonArray("recipients");
			Assertions.assertEquals(2, recipients.size());
			Assertions.assertEquals("a", recipients.get(0).getAsJsonObject().getAsJsonObject("header").get("kid").getAsString());
			Assertions.assertEquals("b", recipients.get(1).getAsJsonObject().getAsJsonObject("header").get("kid").getAsString());
			Assertions.assertEquals(json("{\"shared\":true}"), json.getAsJsonObject("unprotected"));
		}

	}

	@Nested
	@DisplayName("header collisions")
	class Collisions {

		private KeyPair xwingKeyPair;

		@BeforeEach
		void setup() throws GeneralSecurityException {
			xwingKeyPair = KeyPairGenerator.getInstance("X-Wing", XwingProvider.INSTANCE).generateKeyPair();
		}

		@Test
		@DisplayName("encrypt rejects caller-supplied params the library derives (alg, enc)")
		void testRejectsDerivedParams() {
			var builder = JWE.build("payload");

			Assertions.assertThrows(IllegalArgumentException.class, () -> builder.withProtectedHeader(json("{\"alg\":\"A256KW\"}")).encrypt(Enc.A256GCM, kek));
			Assertions.assertThrows(IllegalArgumentException.class, () -> builder.withProtectedHeader(json("{\"enc\":\"A256GCM\"}")).encrypt(Enc.A256GCM, kek));
			Assertions.assertThrows(IllegalArgumentException.class, () -> builder.withUnprotectedHeader(json("{\"enc\":\"A256GCM\"}")).encrypt(Enc.A256GCM, kek));
		}

		@Test
		@DisplayName("encrypt rejects the same param in two header locations")
		void testRejectsCollidingLocations() {
			var builder = JWE.build("payload");
			var withKid = Recipient.withAlg(kek).withClaim("kid", "k");

			Assertions.assertThrows(IllegalArgumentException.class, () -> builder.withProtectedHeader(json("{\"kid\":\"k\"}")).encrypt(Enc.A256GCM, withKid));
			Assertions.assertThrows(IllegalArgumentException.class, () -> builder.withUnprotectedHeader(json("{\"kid\":\"k\"}")).encrypt(Enc.A256GCM, withKid));
			Assertions.assertThrows(IllegalArgumentException.class, () -> builder.withProtectedHeader(json("{\"x\":1}")).withUnprotectedHeader(json("{\"x\":1}")).encrypt(Enc.A256GCM, kek));
		}

		@Test
		@DisplayName("encrypt rejects an empty recipient list")
		void testRejectsNoRecipients() {
			Assertions.assertThrows(IllegalArgumentException.class, () -> JWE.build("payload").encrypt(Enc.A256GCM, new Recipient[0]));
		}

		@Test
		@DisplayName("Integrated Encryption rejects a caller-supplied alg instead of overwriting it")
		void testIntegratedRejectsCallerAlg() {
			var builder = JWE.build("payload").withProtectedHeader(json("{\"alg\":\"HPKE-9\"}"));
			Assertions.assertThrows(IllegalArgumentException.class, () -> builder.encrypt(Alg.hpke9(xwingKeyPair.getPublic())));
		}

	}

	@Nested
	@DisplayName("producer-side crit (RFC 7515 Section 4.1.11)")
	class Crit {

		private KeyPair xwingKeyPair;

		@BeforeEach
		void setup() throws GeneralSecurityException {
			xwingKeyPair = KeyPairGenerator.getInstance("X-Wing", XwingProvider.INSTANCE).generateKeyPair();
		}

		@Test
		@DisplayName("a valid crit round-trips in all three modes")
		void testValidCrit() throws JoseException {
			var header = json("{\"crit\":[\"org.example.v\"],\"org.example.v\":1}");
			var simple = JWE.build("payload").withProtectedHeader(header).encrypt(Enc.A128GCM, kek).toCompactSerialization();
			var multi = JWE.build("payload").withProtectedHeader(header).encrypt(Enc.A128GCM, kek, kek).toJsonSerialization();
			var integrated = JWE.build("payload").withProtectedHeader(header).encrypt(Alg.hpke9(xwingKeyPair.getPublic())).toCompactSerialization();
			Assertions.assertEquals("payload", JWE.parse(simple, "org.example.v").decrypt(kek).payload());
			Assertions.assertEquals("payload", JWE.parse(multi, "org.example.v").decrypt(kek).payload());
			Assertions.assertEquals("payload", JWE.parse(integrated, "org.example.v").decrypt(Alg.hpke9(xwingKeyPair.getPrivate())).payload());
		}

		@Test
		@DisplayName("malformed crit, registered names and absent params are refused when encrypting")
		void testInvalidCrit() {
			for (var header : List.of("{\"crit\":[]}", "{\"crit\":\"x\"}", "{\"crit\":[1]}", "{\"crit\":[\"x\",\"x\"],\"x\":1}", "{\"crit\":[\"kid\"],\"kid\":\"k\"}", "{\"crit\":[\"x\"]}")) {
				var builder = JWE.build("payload").withProtectedHeader(json(header));
				Assertions.assertThrows(IllegalArgumentException.class, () -> builder.encrypt(Enc.A128GCM, kek), header);
				Assertions.assertThrows(IllegalArgumentException.class, () -> builder.encrypt(Enc.A128GCM, kek, kek), header);
				Assertions.assertThrows(IllegalArgumentException.class, () -> builder.encrypt(Alg.hpke9(xwingKeyPair.getPublic())), header);
			}
		}

		@Test
		@DisplayName("a critical param may live in a per-recipient or shared unprotected header, but must then be present for every recipient")
		void testCritParamPresence() throws JoseException {
			var crit = json("{\"crit\":[\"org.example.v\"]}");
			var withParam = Recipient.withAlg(kek).withClaim("org.example.v", 1);
			var withoutParam = Recipient.withAlg(kek);
			Assertions.assertDoesNotThrow(() -> JWE.build("payload").withProtectedHeader(crit).encrypt(Enc.A128GCM, withParam, withParam));
			Assertions.assertThrows(IllegalArgumentException.class, () -> JWE.build("payload").withProtectedHeader(crit).encrypt(Enc.A128GCM, withParam, withoutParam));
			Assertions.assertDoesNotThrow(() -> JWE.build("payload").withProtectedHeader(crit).withUnprotectedHeader(json("{\"org.example.v\":1}")).encrypt(Enc.A128GCM, kek, kek));
			Assertions.assertDoesNotThrow(() -> JWE.build("payload").withProtectedHeader(crit).withUnprotectedHeader(json("{\"org.example.v\":1}")).encrypt(Alg.hpke9(xwingKeyPair.getPublic())));
		}

		@Test
		@DisplayName("crit itself is refused outside the protected header")
		void testCritMustBeProtected() {
			var crit = json("{\"crit\":[\"org.example.v\"],\"org.example.v\":1}");
			Assertions.assertThrows(IllegalArgumentException.class, () -> JWE.build("payload").withUnprotectedHeader(crit).encrypt(Enc.A128GCM, kek));
			Assertions.assertThrows(IllegalArgumentException.class, () -> JWE.build("payload").withUnprotectedHeader(crit).encrypt(Alg.hpke9(xwingKeyPair.getPublic())));
			Assertions.assertThrows(IllegalArgumentException.class, () -> JWE.build("payload").encrypt(Enc.A128GCM, Recipient.withAlg(kek).withClaims(crit)));
			Assertions.assertThrows(IllegalArgumentException.class, () -> JWE.build("payload").encrypt(Enc.A128GCM, Recipient.withAlg(kek).withClaims(crit), Recipient.withAlg(kek)));
		}

	}

	@Test
	@DisplayName("Integrated Encryption refuses a caller-supplied alg in the shared unprotected header too")
	void testIntegratedAlgInUnprotectedHeader() throws GeneralSecurityException {
		var xwingKeyPair = KeyPairGenerator.getInstance("X-Wing", XwingProvider.INSTANCE).generateKeyPair();
		var builder = JWE.build("payload").withUnprotectedHeader(json("{\"alg\":\"HPKE-9\"}"));
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.encrypt(Alg.hpke9(xwingKeyPair.getPublic())));
	}

}
