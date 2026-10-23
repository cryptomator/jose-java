package org.cryptomator.jose.parser;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.cryptomator.jose.Alg;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.JWE;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.JoseException;
import org.cryptomator.jose.JoseParseException;
import org.cryptomator.jose.Recipient;
import org.cryptomator.jose.alg.EcdhEsAlg;
import org.cryptomator.jose.hpke.XwingProvider;
import org.cryptomator.jose.util.Curve;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;

class ParsedJWETest {

	private static final char[] PASSWORD = "secret".toCharArray();

	private ParsedJWE valid;

	@BeforeEach
	void setup() throws JoseParseException {
		// a valid PBES2 (Key Encryption) JWE with a 12-byte iv and a 16-byte tag
		var jwe = JWE.build("payload").encrypt(Enc.A256GCM, Alg.pbes2(PASSWORD, 1000)).toJsonSerialization();
		valid = JWE.parse(jwe);
	}

	@Test
	@DisplayName("the baseline token decrypts")
	void testDecrypt() throws JoseDecryptException {
		Assertions.assertEquals("payload", valid.decrypt(Alg.pbes2(PASSWORD)).payload());
	}

	@Test
	@DisplayName("an empty iv fails with a checked exception")
	void testEmptyIv() {
		var malformed = new ParsedJWE(valid.protectedHeader(), valid.unprotectedHeader(), valid.recipients(), "", valid.ciphertext(), valid.tag(), valid.aad());
		Assertions.assertThrows(JoseDecryptException.class, () -> malformed.decrypt(Alg.pbes2(PASSWORD)));
	}

	@Test
	@DisplayName("an empty tag fails with a checked exception")
	void testEmptyTag() {
		var malformed = new ParsedJWE(valid.protectedHeader(), valid.unprotectedHeader(), valid.recipients(), valid.iv(), valid.ciphertext(), "", valid.aad());
		Assertions.assertThrows(JoseDecryptException.class, () -> malformed.decrypt(Alg.pbes2(PASSWORD)));
	}

	@Test
	@DisplayName("an unsupported enc fails with a checked exception")
	void testUnsupportedEnc() {
		// enc is checked before the CEK is unwrapped, so the recipient/ciphertext need not be valid
		var malformed = malformed("{\"alg\":\"PBES2-HS512+A256KW\",\"enc\":\"A192GCM\"}");
		Assertions.assertThrows(JoseDecryptException.class, () -> malformed.decrypt(Alg.pbes2(PASSWORD)));
	}

	@Test
	@DisplayName("a non-string enc fails with a checked exception")
	void testNonStringEnc() {
		var malformed = malformed("{\"alg\":\"PBES2-HS512+A256KW\",\"enc\":{}}");
		Assertions.assertThrows(JoseDecryptException.class, () -> malformed.decrypt(Alg.pbes2(PASSWORD)));
	}

	@Test
	@DisplayName("non-base64url iv, ciphertext or tag fail with a checked exception")
	void testMalformedBase64Parts() {
		for (var field : List.of("iv", "ciphertext", "tag")) {
			var malformed = new ParsedJWE(valid.protectedHeader(), valid.unprotectedHeader(), valid.recipients(),
					field.equals("iv") ? "!" : valid.iv(), field.equals("ciphertext") ? "!" : valid.ciphertext(), field.equals("tag") ? "!" : valid.tag(), valid.aad());
			Assertions.assertThrows(JoseDecryptException.class, () -> malformed.decrypt(Alg.pbes2(PASSWORD)), field);
		}
	}

	@Test
	@DisplayName("a non-base64url encrypted_key is skipped in favor of a later valid recipient")
	void testMalformedEncryptedKeyIsSkipped() throws JoseDecryptException {
		var broken = valid.recipients().get(0).getAsJsonObject().deepCopy();
		broken.addProperty("encrypted_key", "!");
		var recipients = new JsonArray();
		recipients.add(broken);
		recipients.add(valid.recipients().get(0));
		var withBrokenFirst = new ParsedJWE(valid.protectedHeader(), valid.unprotectedHeader(), recipients, valid.iv(), valid.ciphertext(), valid.tag(), valid.aad());
		Assertions.assertEquals("payload", withBrokenFirst.decrypt(Alg.pbes2(PASSWORD)).payload());
	}

	@Test
	@DisplayName("an alg throwing an unchecked exception on a recipient does not abort the loop")
	void testUncheckedAlgFailureIsSkipped() throws Exception {
		var ecKeyGen = KeyPairGenerator.getInstance("EC");
		ecKeyGen.initialize(new ECGenParameterSpec("secp384r1"));
		var ecKeyPair = ecKeyGen.generateKeyPair();
		var jwe = JWE.build("payload").encrypt(Enc.A256GCM, Alg.ecdhEs(ecKeyPair.getPublic()), Alg.pbes2(PASSWORD, 1000)).toJsonSerialization();
		var misconfigured = new EcdhEsAlg(EcdhEsAlg.Type.ECDH_ES_A256KW, Curve.P384, null, null); // matches the first recipient's alg, throws IllegalStateException (no private key)

		Assertions.assertEquals("payload", JWE.parse(jwe).decrypt(misconfigured, Alg.pbes2(PASSWORD)).payload());
	}

	@Test
	@DisplayName("a non-string ek fails with a checked exception")
	void testNonStringEk() throws NoSuchAlgorithmException {
		// ek is checked before decapsulation, so any private key of the right type works
		var keyPair = KeyPairGenerator.getInstance("X-Wing", XwingProvider.INSTANCE).generateKeyPair();
		var malformed = malformed("{\"alg\":\"HPKE-9-KE\",\"enc\":\"A256GCM\",\"ek\":{}}");
		Assertions.assertThrows(JoseDecryptException.class, () -> malformed.decrypt(Alg.hpke9Ke(keyPair.getPrivate())));
	}

	@Nested
	@DisplayName("decrypt by kid")
	class ByKid {

		private static final SecretKey KEK_A = new SecretKeySpec(new byte[32], "AES");
		private static final SecretKey KEK_B = new SecretKeySpec(new byte[]{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, "AES");

		private ParsedJWE twoRecipients;

		@BeforeEach
		void setup() throws JoseParseException {
			var jwe = JWE.build("payload").encrypt(Enc.A256GCM, Recipient.withAlg(Alg.a256kw(KEK_A)).withClaim("kid", "a"), Recipient.withAlg(Alg.a256kw(KEK_B)).withClaim("kid", "b")).toJsonSerialization();
			twoRecipients = JWE.parse(jwe);
		}

		@Test
		@DisplayName("selects the recipient with the matching kid")
		void testMatch() throws JoseDecryptException {
			Assertions.assertEquals("b", twoRecipients.decrypt("b", Alg.a256kw(KEK_B)).unprotectedHeader().get("kid").getAsString());
			Assertions.assertEquals("a", twoRecipients.decrypt("a", Alg.a256kw(KEK_A)).unprotectedHeader().get("kid").getAsString());
		}

		@Test
		@DisplayName("does not fall back to other recipients")
		void testNoFallback() {
			var thrown = Assertions.assertThrows(JoseDecryptException.class, () -> twoRecipients.decrypt("a", Alg.a256kw(KEK_B)));
			Assertions.assertEquals(1, thrown.getSuppressed().length); // only recipient a was tried, with the wrong key
		}

		@Test
		@DisplayName("an unknown kid fails without trying any recipient")
		void testUnknownKid() {
			var thrown = Assertions.assertThrows(JoseDecryptException.class, () -> twoRecipients.decrypt("c", Alg.a256kw(KEK_A)));
			Assertions.assertTrue(thrown.getMessage().contains("No recipient with kid"));
		}

		@Test
		@DisplayName("a kid shared by several recipients is ambiguous")
		void testAmbiguousKid() throws JoseParseException {
			var jwe = JWE.build("payload").encrypt(Enc.A256GCM, Recipient.withAlg(Alg.a256kw(KEK_A)).withClaim("kid", "x"), Recipient.withAlg(Alg.a256kw(KEK_B)).withClaim("kid", "x")).toJsonSerialization();
			var parsed = JWE.parse(jwe);
			var thrown = Assertions.assertThrows(JoseDecryptException.class, () -> parsed.decrypt("x", Alg.a256kw(KEK_A)));
			Assertions.assertTrue(thrown.getMessage().contains("Ambiguous"));
		}

		@Test
		@DisplayName("a kid in the protected header selects the single recipient of a compact JWE")
		void testKidInProtectedHeader() throws JoseException {
			var jwe = JWE.build("payload").encrypt(Enc.A256GCM, Recipient.withAlg(Alg.a256kw(KEK_A)).withClaim("kid", "p")).toCompactSerialization();
			Assertions.assertEquals("payload", JWE.parse(jwe).decrypt("p", Alg.a256kw(KEK_A)).payload());
		}

	}

	private ParsedJWE malformed(String protectedHeaderJson) {
		var recipient = new JsonObject();
		recipient.addProperty("encrypted_key", "AA");
		var recipients = new JsonArray();
		recipients.add(recipient);
		return new ParsedJWE(base64url(protectedHeaderJson), new JsonObject(), recipients, "", "AA", "", "");
	}

	private static String base64url(String json) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
	}
}
