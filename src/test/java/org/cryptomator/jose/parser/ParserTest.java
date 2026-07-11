package org.cryptomator.jose.parser;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.cryptomator.jose.Alg;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.JWE;
import org.cryptomator.jose.JoseParseException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

class ParserTest {

	private JsonObject validJwe() {
		// a valid PBES2 JWE carries enc in the protected header
		var jwe = JWE.build("payload").encrypt(Enc.A256GCM, Alg.pbes2("secret".toCharArray(), 10)).toJsonSerialization();
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
}
