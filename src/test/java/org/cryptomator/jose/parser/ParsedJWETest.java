package org.cryptomator.jose.parser;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.cryptomator.jose.Alg;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.JWE;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.JoseParseException;
import org.cryptomator.jose.hpke.XwingProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

class ParsedJWETest {

	private static final char[] PASSWORD = "secret".toCharArray();

	private ParsedJWE valid;

	@BeforeEach
	void setup() throws JoseParseException {
		// a valid PBES2 (Key Encryption) JWE with a 12-byte iv and a 16-byte tag
		var jwe = JWE.build("payload").encrypt(Enc.A256GCM, Alg.pbes2(PASSWORD, 10)).toJsonSerialization();
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
	@DisplayName("a non-string ek fails with a checked exception")
	void testNonStringEk() throws NoSuchAlgorithmException {
		// ek is checked before decapsulation, so any private key of the right type works
		var keyPair = KeyPairGenerator.getInstance("X-Wing", XwingProvider.INSTANCE).generateKeyPair();
		var malformed = malformed("{\"alg\":\"HPKE-9-KE\",\"enc\":\"A256GCM\",\"ek\":{}}");
		Assertions.assertThrows(JoseDecryptException.class, () -> malformed.decrypt(Alg.hpke9Ke(keyPair.getPrivate())));
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
