package org.cryptomator.jose.parser;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.cryptomator.jose.Alg;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.JWE;
import org.cryptomator.jose.JoseException;
import org.cryptomator.jose.JoseParseException;
import org.cryptomator.jose.hpke.XwingProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;

class ParserTest {

	private JsonObject validJwe() {
		// a valid PBES2 JWE carries enc in the protected header
		var jwe = JWE.build("payload").encrypt(Enc.A256GCM, Alg.pbes2("secret".toCharArray(), 1000)).toJsonSerialization();
		return JsonParser.parseString(jwe).getAsJsonObject();
	}

	/// RFC 7516 §4: the JOSE Header must not contain duplicate parameter names across the protected, shared unprotected and per-recipient headers.
	@Test
	@DisplayName("enc duplicated in the shared unprotected header is rejected")
	void testDuplicateEncInSharedHeader() {
		var json = validJwe();
		var unprotected = new JsonObject();
		unprotected.addProperty("enc", "A128GCM"); // enc is already in the protected header
		json.add("unprotected", unprotected);

		var thrown = Assertions.assertThrows(JoseParseException.class, () -> JWE.parse(json.toString()));
		Assertions.assertTrue(thrown.getMessage().contains("Duplicate header parameter: enc"));
	}

	@Test
	@DisplayName("enc duplicated in a per-recipient header is rejected")
	void testDuplicateEncInRecipientHeader() {
		var json = validJwe();
		var recipient = json.getAsJsonArray("recipients").get(0).getAsJsonObject();
		var header = new JsonObject();
		header.addProperty("enc", "A128GCM"); // enc is already in the protected header
		recipient.add("header", header);

		var thrown = Assertions.assertThrows(JoseParseException.class, () -> JWE.parse(json.toString()));
		Assertions.assertTrue(thrown.getMessage().contains("Duplicate header parameter: enc"));
	}

	@Test
	@DisplayName("a protected header that is not a JSON object is rejected")
	void testInvalidProtectedHeader() {
		var json = validJwe();
		json.addProperty("protected", Base64.getUrlEncoder().withoutPadding().encodeToString("\"not an object\"".getBytes(StandardCharsets.UTF_8)));

		Assertions.assertThrows(JoseParseException.class, () -> JWE.parse(json.toString()));
	}

	@Test
	@DisplayName("a non-string alg is rejected")
	void testNonStringAlg() {
		var json = validJwe();
		json.addProperty("protected", base64url("{\"alg\":{},\"enc\":\"A256GCM\"}")); // alg is a JSON object, not a string

		var thrown = Assertions.assertThrows(JoseParseException.class, () -> JWE.parse(json.toString()));
		Assertions.assertTrue(thrown.getMessage().contains("alg"));
	}

	@Test
	@DisplayName("a missing alg is rejected")
	void testMissingAlg() {
		var json = validJwe();
		json.addProperty("protected", base64url("{\"enc\":\"A256GCM\"}")); // no alg anywhere

		Assertions.assertThrows(JoseParseException.class, () -> JWE.parse(json.toString()));
	}

	@Test
	@DisplayName("zip is rejected wherever it occurs")
	void testZipRejected() {
		var inProtected = validJwe();
		inProtected.addProperty("protected", base64url("{\"alg\":\"PBES2-HS512+A256KW\",\"enc\":\"A256GCM\",\"zip\":\"DEF\"}"));
		var inUnprotected = validJwe();
		inUnprotected.add("unprotected", JsonParser.parseString("{\"zip\":\"DEF\"}").getAsJsonObject());
		var inRecipient = validJwe();
		inRecipient.getAsJsonArray("recipients").get(0).getAsJsonObject().add("header", JsonParser.parseString("{\"zip\":\"DEF\"}").getAsJsonObject());
		var compact = inProtected.get("protected").getAsString() + ".AA.AA.AA.AA";

		for (var token : List.of(inProtected.toString(), inUnprotected.toString(), inRecipient.toString(), compact)) {
			var thrown = Assertions.assertThrows(JoseParseException.class, () -> JWE.parse(token));
			Assertions.assertTrue(thrown.getMessage().contains("zip"), token);
		}
	}

	@Test
	@DisplayName("a compact serialization without alg is rejected")
	void testCompactMissingAlg() {
		var compact = base64url("{\"enc\":\"A256GCM\"}") + ".AA.AA.AA.AA";
		Assertions.assertThrows(JoseParseException.class, () -> JWE.parse(compact));
	}

	@Test
	@DisplayName("members of the wrong JSON type are rejected with a checked exception")
	void testMemberTypes() {
		var wrongTypes = List.of(
				"{\"protected\":1}", "{\"aad\":[]}", "{\"iv\":{}}", "{\"tag\":true}", "{\"ciphertext\":1}", "{\"unprotected\":\"x\"}",
				"{\"recipients\":{}}", "{\"recipients\":[{\"encrypted_key\":1}]}", "{\"recipients\":[{\"encrypted_key\":\"AA\",\"header\":[]}]}");
		for (var patch : wrongTypes) {
			var json = validJwe();
			JsonParser.parseString(patch).getAsJsonObject().entrySet().forEach(e -> json.add(e.getKey(), e.getValue()));
			Assertions.assertThrows(JoseParseException.class, () -> JWE.parse(json.toString()), patch);
		}
	}

	@Test
	@DisplayName("whitespace around the JSON serialization is tolerated")
	void testSurroundingWhitespace() throws JoseException {
		var jwe = validJwe().toString();
		Assertions.assertDoesNotThrow(() -> JWE.parse("  " + jwe + "  "));
		Assertions.assertDoesNotThrow(() -> JWE.parse("\n\t" + jwe + "\n"));
	}

	@Nested
	@DisplayName("crit")
	class Crit {

		private static final SecretKey KEK = new SecretKeySpec(new byte[32], "AES");

		// a valid A256KW compact JWE with the given protected header params (besides alg/enc)
		private String jweWithProtected(String protectedExtras) {
			return JWE.build("payload").withProtectedHeader(JsonParser.parseString(protectedExtras).getAsJsonObject()).encrypt(Enc.A128GCM, Alg.a256kw(KEK)).toCompactSerialization();
		}

		@Test
		@DisplayName("an understood critical param parses and decrypts")
		void testUnderstood() throws JoseException {
			var jwe = jweWithProtected("{\"crit\":[\"org.example.v\"],\"org.example.v\":1}");
			Assertions.assertEquals("payload", JWE.parse(jwe, "org.example.v").decrypt(Alg.a256kw(KEK)).payload());
		}

		@Test
		@DisplayName("a critical param that is not understood is rejected when parsing")
		void testNotUnderstood() {
			var jwe = jweWithProtected("{\"crit\":[\"org.example.v\"],\"org.example.v\":1}");
			var thrown = Assertions.assertThrows(JoseParseException.class, () -> JWE.parse(jwe));
			Assertions.assertTrue(thrown.getMessage().contains("not understood"));
			Assertions.assertThrows(JoseParseException.class, () -> JWE.parse(jwe, "org.example.other"));
		}

		@Test
		@DisplayName("all listed critical params must be understood")
		void testAllMustBeUnderstood() throws JoseException {
			var jwe = jweWithProtected("{\"crit\":[\"a\",\"b\"],\"a\":1,\"b\":2}");
			Assertions.assertThrows(JoseParseException.class, () -> JWE.parse(jwe, "a"));
			Assertions.assertEquals("payload", JWE.parse(jwe, "a", "b").decrypt(Alg.a256kw(KEK)).payload());
		}

		@Test
		@DisplayName("extensions implemented by the library (ek) need not be declared")
		void testImplementedExtension() throws Exception {
			var keyPair = KeyPairGenerator.getInstance("X-Wing", XwingProvider.INSTANCE).generateKeyPair();
			var jwe = JWE.build("payload").withProtectedHeader(JsonParser.parseString("{\"crit\":[\"ek\"]}").getAsJsonObject()).encrypt(Enc.A256GCM, Alg.hpke9Ke(keyPair.getPublic())).toCompactSerialization();
			Assertions.assertEquals("payload", JWE.parse(jwe).decrypt(Alg.hpke9Ke(keyPair.getPrivate())).payload());
		}

		@Test
		@DisplayName("psk_id is not implemented and therefore not understood")
		void testPskIdNotUnderstood() {
			var jwe = jweWithProtected("{\"crit\":[\"psk_id\"],\"psk_id\":\"x\"}");
			Assertions.assertThrows(JoseParseException.class, () -> JWE.parse(jwe));
		}

		@Test
		@DisplayName("a registered header parameter must not be listed in crit")
		void testRegisteredName() {
			var jwe = jweWithProtected("{\"crit\":[\"kid\"],\"kid\":\"k\"}");
			Assertions.assertThrows(JoseParseException.class, () -> JWE.parse(jwe, "kid"));
		}

		@Test
		@DisplayName("crit must be a non-empty array of unique strings")
		void testMalformedCrit() {
			for (var crit : List.of("\"org.example.v\"", "[]", "[1]", "[\"org.example.v\",\"org.example.v\"]")) {
				var jwe = jweWithProtected("{\"crit\":" + crit + ",\"org.example.v\":1}");
				Assertions.assertThrows(JoseParseException.class, () -> JWE.parse(jwe, "org.example.v"), crit);
			}
		}

		@Test
		@DisplayName("a critical param that is absent from the header is rejected")
		void testCritParamAbsent() {
			var jwe = jweWithProtected("{\"crit\":[\"org.example.v\"]}");
			var thrown = Assertions.assertThrows(JoseParseException.class, () -> JWE.parse(jwe, "org.example.v"));
			Assertions.assertTrue(thrown.getMessage().contains("absent"));
		}

		@Test
		@DisplayName("crit outside the protected header is rejected")
		void testCritNotProtected() {
			var jwe = JsonParser.parseString(JWE.build("payload").encrypt(Enc.A128GCM, Alg.a256kw(KEK)).toJsonSerialization()).getAsJsonObject();
			var inUnprotected = jwe.deepCopy();
			inUnprotected.add("unprotected", JsonParser.parseString("{\"crit\":[\"org.example.v\"],\"org.example.v\":1}").getAsJsonObject());
			var inRecipient = jwe.deepCopy();
			inRecipient.getAsJsonArray("recipients").get(0).getAsJsonObject().add("header", JsonParser.parseString("{\"crit\":[\"org.example.v\"],\"org.example.v\":1}").getAsJsonObject());

			for (var json : List.of(inUnprotected, inRecipient)) {
				var thrown = Assertions.assertThrows(JoseParseException.class, () -> JWE.parse(json.toString(), "org.example.v"));
				Assertions.assertTrue(thrown.getMessage().contains("protected header"));
			}
		}

	}

	private static String base64url(String json) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
	}
}
