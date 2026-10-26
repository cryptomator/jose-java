package org.cryptomator.jose;

import org.cryptomator.jose.util.ArrayUtil;
import org.cryptomator.jose.util.Base64Url;
import org.cryptomator.jose.util.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.stream.Stream;

class JWKTest {

	@Nested
	@DisplayName("AKP JWK")
	class Akp {

		// the "priv" value (X-Wing seed) of the AKP JWK from draft-ietf-jose-hpke-pq-pqt-01 Appendix A.4
		private static final String PRIV = "q_aDEMZpRAjbiqHwO23vKcgImYieSqUsCK7wWZEsq8Y";

		@Test
		@DisplayName("a valid AKP private JWK parses")
		void testValid() throws JoseParseException {
			var key = JWK.parse("{\"kty\":\"AKP\",\"alg\":\"HPKE-9-KE\",\"priv\":\"" + PRIV + "\"}");
			Assertions.assertInstanceOf(PrivateKey.class, key);
		}

		@Test
		@DisplayName("a non-string alg is rejected")
		void testNonStringAlg() {
			Assertions.assertThrows(JoseParseException.class, () -> JWK.parse("{\"kty\":\"AKP\",\"alg\":{},\"priv\":\"" + PRIV + "\"}"));
		}

		@Test
		@DisplayName("a non-string priv is rejected")
		void testNonStringPriv() {
			Assertions.assertThrows(JoseParseException.class, () -> JWK.parse("{\"kty\":\"AKP\",\"alg\":\"HPKE-9-KE\",\"priv\":{}}"));
		}

		@Test
		@DisplayName("an alg that merely starts with HPKE-9 is rejected")
		void testAlgPrefixNotAccepted() {
			var thrown = Assertions.assertThrows(JoseParseException.class, () -> JWK.parse("{\"kty\":\"AKP\",\"alg\":\"HPKE-90\",\"priv\":\"" + PRIV + "\"}"));
			Assertions.assertTrue(thrown.getMessage().contains("Unsupported AKP algorithm"));
		}
	}

	@Nested
	@DisplayName("EC JWK")
	class Ec {

		// the P-256 key pair from draft-ietf-jose-hpke-encrypt-22 Appendix A.1
		private static final String X = "qy-BxXhaelX9Fqe8muRTu8HhseHYgMMGxyfAnIy0MC0";
		private static final String Y = "ctfHN7Y4pkj7vZI-sgJ6BqsYwG-PDnB8j7TsfzHHJOI";
		private static final String D = "aAKxBMAkNm2AZDGv7LN5yodDwahJ5rKbrgiiz3dUIH4";

		private static String jwk(String x, String y, String d) {
			return "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"" + (d == null ? "" : ",\"d\":\"" + d + "\"") + "}";
		}

		@Test
		@DisplayName("valid public and private JWKs parse")
		void testValid() throws JoseParseException {
			Assertions.assertInstanceOf(ECPublicKey.class, JWK.parse(jwk(X, Y, null)));
			Assertions.assertInstanceOf(ECPrivateKey.class, JWK.parse(jwk(X, Y, D)));
		}

		static Stream<Arguments> wrongLengths() {
			var x = Base64Url.decode(X);
			var shorter = Base64Url.encode(Arrays.copyOfRange(x, 1, x.length)); // 31 bytes, leading zero stripped
			var longer = Base64Url.encode(ArrayUtil.concat(new byte[1], x)); // 33 bytes, extra leading zero: same value, different encoding
			return Stream.of(
					Arguments.of("x shorter", jwk(shorter, Y, null)),
					Arguments.of("x longer", jwk(longer, Y, null)),
					Arguments.of("y shorter", jwk(X, shorter, null)),
					Arguments.of("y longer", jwk(X, longer, null)),
					Arguments.of("d shorter", jwk(X, Y, shorter)),
					Arguments.of("d longer", jwk(X, Y, longer)),
					Arguments.of("x empty", jwk("", Y, null)),
					Arguments.of("x for P-384 on P-256", jwk(Base64Url.encode(new byte[48]), Y, null))
			);
		}

		@ParameterizedTest(name = "{0}")
		@MethodSource("wrongLengths")
		@DisplayName("coordinates and scalars must be exactly the curve's coordinate length (RFC 7518 Section 6.2.1.2)")
		void testWrongLength(String name, String json) {
			var thrown = Assertions.assertThrows(JoseParseException.class, () -> JWK.parse(json));
			Assertions.assertTrue(thrown.getMessage().contains("32 bytes"), thrown.getMessage());
		}

		@ParameterizedTest(name = "d = {0}")
		@CsvSource({
				"0000000000000000000000000000000000000000000000000000000000000000", // zero: point at infinity
				"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", // n, the order of P-256
				"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632552", // n + 1, aliases d = 1
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // 2^256 - 1
		})
		@DisplayName("private scalars outside [1, n-1] are rejected")
		void testScalarOutOfRange(@Hex byte[] d) {
			Assertions.assertThrows(JoseParseException.class, () -> JWK.parse(jwk(X, Y, Base64Url.encode(d))));
		}

		@Test
		@DisplayName("the largest valid scalar n-1 is accepted")
		void testScalarAtUpperBound() throws JoseParseException {
			var nMinusOne = Base64Url.encode(HexFormat.of().parseHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550"));
			Assertions.assertInstanceOf(ECPrivateKey.class, JWK.parse(jwk(X, Y, nMinusOne)));
		}

	}

	@Test
	@DisplayName("lenient JSON is rejected")
	void testStrictJson() {
		Assertions.assertThrows(JoseParseException.class, () -> JWK.parse("{kty: \"EC\"}"));
		Assertions.assertThrows(JoseParseException.class, () -> JWK.parse("{\"kty\": \"EC\"} // comment"));
		Assertions.assertThrows(JoseParseException.class, () -> JWK.parse("[]"));
	}

	@Test
	@DisplayName("a non-string kty is rejected")
	void testNonStringKty() {
		Assertions.assertThrows(JoseParseException.class, () -> JWK.parse("{\"kty\":{}}"));
	}

	@Test
	@DisplayName("non-string or non-base64url EC members are rejected with a checked exception")
	void testMalformedEcMembers() {
		Assertions.assertThrows(JoseParseException.class, () -> JWK.parse("{\"kty\":\"EC\",\"crv\":{},\"x\":\"AA\",\"y\":\"AA\"}"));
		Assertions.assertThrows(JoseParseException.class, () -> JWK.parse("{\"kty\":\"EC\",\"crv\":null,\"x\":\"AA\",\"y\":\"AA\"}"));
		Assertions.assertThrows(JoseParseException.class, () -> JWK.parse("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":1,\"y\":\"AA\"}"));
		Assertions.assertThrows(JoseParseException.class, () -> JWK.parse("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"!!\",\"y\":\"AA\"}"));
		Assertions.assertThrows(JoseParseException.class, () -> JWK.parse("{\"kty\":\"EC\",\"crv\":\"P-256\",\"d\":[]}"));
	}
}
