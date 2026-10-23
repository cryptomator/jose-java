package org.cryptomator.jose;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Stream;

class JWSTest {

	private static final SecretKey KEY = new SecretKeySpec(new byte[64], "HmacSHA256");

	private static JsonObject json(String json) {
		return JsonParser.parseString(json).getAsJsonObject();
	}

	/// test vector from [RFC 7515, Appendix A.1](https://www.rfc-editor.org/rfc/rfc7515#appendix-A.1)
	@Nested
	@DisplayName("RFC 7515 Appendix A.1 (HS256)")
	class Rfc7515AppendixA1 {

		private static final String TOKEN = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
		private static final SecretKey RFC_KEY = new SecretKeySpec(Base64.getUrlDecoder().decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"), "HmacSHA256");

		@Test
		@DisplayName("verifies and exposes payload and header")
		void testVerify() throws JoseException {
			var verified = JWS.parse(TOKEN).verify(MacAlg.hs256(RFC_KEY));
			Assertions.assertEquals("{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}", verified.payload());
			Assertions.assertEquals("JWT", verified.protectedHeader().get("typ").getAsString());
			Assertions.assertEquals("HS256", verified.protectedHeader().get("alg").getAsString());
		}

		@Test
		@DisplayName("a wrong key fails verification")
		void testWrongKey() throws JoseParseException {
			var parsed = JWS.parse(TOKEN);
			Assertions.assertThrows(JoseVerifyException.class, () -> parsed.verify(MacAlg.hs256(KEY)));
		}

		@Test
		@DisplayName("a tampered payload fails verification")
		void testTamperedPayload() throws JoseParseException {
			var parts = TOKEN.split("\\.");
			var tampered = parts[0] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString("{\"iss\":\"eve\"}".getBytes()) + "." + parts[2];
			var parsed = JWS.parse(tampered);
			Assertions.assertEquals("{\"iss\":\"eve\"}", parsed.unverifiedPayload());
			Assertions.assertThrows(JoseVerifyException.class, () -> parsed.verify(MacAlg.hs256(RFC_KEY)));
		}

		@Test
		@DisplayName("an alg that does not match is not tried")
		void testAlgMismatch() throws JoseParseException {
			var parsed = JWS.parse(TOKEN);
			var thrown = Assertions.assertThrows(JoseVerifyException.class, () -> parsed.verify(MacAlg.hs512(RFC_KEY)));
			Assertions.assertTrue(thrown.getMessage().contains("HS256"));
			Assertions.assertDoesNotThrow(() -> parsed.verify(MacAlg.hs512(RFC_KEY), MacAlg.hs256(RFC_KEY)));
		}

	}

	@ParameterizedTest
	@MethodSource
	@DisplayName("sign and verify round trip with typ and kid")
	void testRoundTrip(Function<SecretKey, MacAlg> alg) throws JoseException {
		var header = json("{\"typ\":\"JWT\",\"kid\":\"masterkey.cryptomator\"}");
		var token = JWS.build("{\"format\":8}").withProtectedHeader(header).sign(alg.apply(KEY));

		var verified = JWS.parse(token).verify(alg.apply(KEY));
		Assertions.assertEquals("{\"format\":8}", verified.payload());
		Assertions.assertEquals(alg.apply(KEY).name(), verified.protectedHeader().get("alg").getAsString());
		Assertions.assertEquals("JWT", verified.protectedHeader().get("typ").getAsString());
		Assertions.assertEquals("masterkey.cryptomator", verified.protectedHeader().get("kid").getAsString());
	}

	static Stream<Function<SecretKey, MacAlg>> testRoundTrip() {
		return Stream.of(MacAlg::hs256, MacAlg::hs384, MacAlg::hs512);
	}

	@Test
	@DisplayName("verify tries every provided algorithm whose name matches (key rotation)")
	void testKeyRotation() throws JoseException {
		var oldKey = new SecretKeySpec(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}, "HmacSHA256");
		var unrelatedKey = new SecretKeySpec(new byte[32], "HmacSHA256");
		var token = JWS.build("p").sign(MacAlg.hs256(oldKey));

		Assertions.assertEquals("p", JWS.parse(token).verify(MacAlg.hs256(KEY), MacAlg.hs256(oldKey)).payload());
		var thrown = Assertions.assertThrows(JoseVerifyException.class, () -> JWS.parse(token).verify(MacAlg.hs256(KEY), MacAlg.hs256(unrelatedKey)));
		Assertions.assertEquals("Invalid signature", thrown.getMessage());
	}

	@Test
	@DisplayName("keys shorter than the hash output are rejected")
	void testShortKey() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> MacAlg.hs256(new SecretKeySpec(new byte[31], "HmacSHA256")));
		Assertions.assertThrows(IllegalArgumentException.class, () -> MacAlg.hs384(new SecretKeySpec(new byte[47], "HmacSHA384")));
		Assertions.assertThrows(IllegalArgumentException.class, () -> MacAlg.hs512(new SecretKeySpec(new byte[63], "HmacSHA512")));
		Assertions.assertDoesNotThrow(() -> MacAlg.hs512(new SecretKeySpec(new byte[64], "HmacSHA512")));
	}

	@Test
	@DisplayName("sign rejects a caller-supplied alg and the unsupported b64")
	void testSignRejectsReservedParams() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> JWS.build("p").withProtectedHeader(json("{\"alg\":\"HS256\"}")).sign(MacAlg.hs256(KEY)));
		Assertions.assertThrows(IllegalArgumentException.class, () -> JWS.build("p").withProtectedHeader(json("{\"b64\":false}")).sign(MacAlg.hs256(KEY)));
	}

	@Test
	@DisplayName("parse rejects malformed tokens")
	void testParseRejectsMalformed() {
		var valid = JWS.build("p").sign(MacAlg.hs256(KEY));
		var parts = valid.split("\\.");
		for (var token : List.of("a.b", "a.b.c.d", "!." + parts[1] + "." + parts[2], parts[0] + ".!." + parts[2], parts[0] + "." + parts[1] + ".!",
				Base64.getUrlEncoder().withoutPadding().encodeToString("{\"typ\":\"JWT\"}".getBytes()) + "." + parts[1] + "." + parts[2],
				Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"HS256\",\"b64\":false}".getBytes()) + "." + parts[1] + "." + parts[2])) {
			Assertions.assertThrows(JoseParseException.class, () -> JWS.parse(token), token);
		}
	}

	@Test
	@DisplayName("crit must be understood by the caller")
	void testCrit() throws JoseException {
		var token = JWS.build("p").withProtectedHeader(json("{\"crit\":[\"org.example.v\"],\"org.example.v\":1}")).sign(MacAlg.hs256(KEY));
		Assertions.assertThrows(JoseParseException.class, () -> JWS.parse(token));
		Assertions.assertEquals("p", JWS.parse(token, "org.example.v").verify(MacAlg.hs256(KEY)).payload());

		var registered = JWS.build("p").withProtectedHeader(json("{\"crit\":[\"kid\"],\"kid\":\"k\"}")).sign(MacAlg.hs256(KEY));
		Assertions.assertThrows(JoseParseException.class, () -> JWS.parse(registered, "kid"));
	}

}
