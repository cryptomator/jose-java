package org.cryptomator.jose;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.cryptomator.jose.hpke.XwingProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

class RecipientTest {

	private final SymmetricKeyAlg kek = Alg.a256kw(new SecretKeySpec(new byte[32], "AES"));
	private KeyPair ecKeyPair;
	private KeyPair xwingKeyPair;

	@BeforeEach
	void setup() throws GeneralSecurityException {
		var ecKeyGen = KeyPairGenerator.getInstance("EC");
		ecKeyGen.initialize(new ECGenParameterSpec("secp384r1"));
		ecKeyPair = ecKeyGen.generateKeyPair();
		xwingKeyPair = KeyPairGenerator.getInstance("X-Wing", XwingProvider.INSTANCE).generateKeyPair();
	}

	private static JsonObject json(String json) {
		return JsonParser.parseString(json).getAsJsonObject();
	}

	@Test
	@DisplayName("withClaim overloads add params of the matching JSON type")
	void testWithClaimTypes() {
		var recipient = Recipient.withAlg(kek)
				.withClaim("kid", "k")
				.withClaim("n", 3)
				.withClaim("b", true)
				.withClaim("o", json("{\"x\":1}"));
		Assertions.assertEquals(json("{\"kid\":\"k\",\"n\":3,\"b\":true,\"o\":{\"x\":1}}"), recipient.header());
	}

	@Test
	@DisplayName("withClaim replaces an existing param, withClaims replaces all")
	void testReplace() {
		var recipient = Recipient.withAlg(kek).withClaim("kid", "a").withClaim("x", 1);
		Assertions.assertEquals(json("{\"kid\":\"b\",\"x\":1}"), recipient.withClaim("kid", "b").header());
		Assertions.assertEquals(json("{\"y\":2}"), recipient.withClaims(json("{\"y\":2}")).header());
	}

	@Test
	@DisplayName("immutable: withers return copies, header() returns a copy")
	void testImmutability() {
		var header = json("{\"kid\":\"a\"}");
		var recipient = Recipient.withAlg(kek).withClaims(header);
		header.addProperty("kid", "b");
		recipient.header().addProperty("kid", "c");
		var replaced = recipient.withClaim("kid", "d");

		Assertions.assertEquals("a", recipient.header().get("kid").getAsString());
		Assertions.assertEquals("d", replaced.header().get("kid").getAsString());
	}

	@Test
	@DisplayName("withClaim/withClaims reject alg-generated params immediately")
	void testRejectsGeneratedParams() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> Recipient.withAlg(kek).withClaim("alg", "A256KW"));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Recipient.withAlg(Alg.ecdhEs(ecKeyPair.getPublic())).withClaim("epk", new JsonObject()));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Recipient.withAlg(Alg.pbes2("secret".toCharArray(), 1000)).withClaim("p2c", 1));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Recipient.withAlg(Alg.hpke9Ke(xwingKeyPair.getPublic())).withClaims(json("{\"ek\":\"\"}")));
	}

	@Test
	@DisplayName("withClaim accepts a param that only another alg would generate")
	void testAcceptsForeignGeneratedParam() {
		Assertions.assertDoesNotThrow(() -> Recipient.withAlg(kek).withClaim("epk", new JsonObject())); // A256KW does not generate epk
	}

}
