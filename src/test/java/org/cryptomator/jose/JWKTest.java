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
import org.junit.jupiter.params.provider.ValueSource;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Optional;
import java.util.stream.Stream;

class JWKTest {

	@Nested
	@DisplayName("AKP JWK")
	class Akp {

		// the HPKE-9-KE private JWK from draft-ietf-jose-hpke-pq-pqt-01 Appendix A.4: "pub" is the 1216-byte X-Wing public key, "priv" the 32-byte seed
		private static final String PUB = "8rGsDcYDVYgHXJdoG_y4snlf_zZ2J7IJ_dyGafoU-8PBqdSb4dKAAggLvULOi_kwqxCdLXqh7sinPlUPEQAXeaITnOkYJhCJN_tpWBBbZclC4sAXNHItUAV4KfAmEgyll0KiqKRohYQjhwSlSAQhA9NwAPJhYMgZPWkDf1zFJexT_prKclLGRzU-AkuACumcboErJqGYIRdXVfN7JqfIXfcNI_QCSpcpuAk_wMOWxOIj2WxdCMMfd1QBFKoAi1cM-_cuL1JWwOK5SsC7FKg5YJZdZPJ53RkFUusZPrhcWsZMsOFXJmgOjeV9bUWA1npKEJt7nDeU9EGbICVel-RChriHe1tcx4OFgUCrCBvEpJl9d0am5jqwYQB-WmwVZ3IFVHM2c5NCb_MHhknJsaCqrSMmEUJ7XBpTWbdUlMNMMiq9Pcd2WwvMyoZmNac_xKmk5VxkBqorWUZ3ieVwcGYt7cZO2mvJwilCccsz6TTIZnuymJU57-J510EbVfGXSBN3_BCpfwHAAqV-rZab5oWPFeYQikjAHieblCgN7bSKl6U-NCpoaPA-n1Q3jMY-vzFy4iaM8ThfoXdzXQo0oLCvyOZ4aqlv4EqYQRFh51RN6Jkyk5eqUUaHmaAV_yyj7wBEkZNIDWNOy7ZAunaDl5tXFpUaPmHLQ4RQV1fCA8Y27gQ_4nOY2zdHhnq12WOrvNN-DrdGI0ShpNWzARMtM6yiDXUV2yR_b6KTDyq0YyMzQCHBQhscrXCN2QxXd4hHj-gjZzoJlim6XybGlrG6EaMkvIKfwuhZ7oxRTuC3hGJBSkMptQNg3Th4luol-Fl7WepM0vOYOVyYdRANeszJ6WTKZJCtzUhPcSBzeImXaDqNeCAt9jIBXpoJX6m8RViM4bW8YgtR6vK2ceNW5yWCAfOA9NmiBDAhFaMNTnueistr2eEJhzFZ2wJsT1MG-vG2EIyuUNBqwlNjVvR4vfEAWOmeBuA5v7By3ycsOMFv2hk2eGssIzmE86ZOj5Oj11QWFPRrSMx5zLdDu0ep_pPCYNUicStcDtIvy-pfJ2uEdBoJ5hdE9duIGZOlTeozIWdeEcBrv-sEJmKk7hNeOSBpVpAlYDTDTVpvOik-mJAR_hbNnfCY55sFD7C-zxOfrjQdYwWLDSSH5mV4IQKzseJ8x1w5cbWWzbUqF2pNZBDEAjSpiqqVxgOAikaOwzMaWAERNOeX6NFYkmga2nREl5t46woTvbqBTSxBMOxcS3KCbzmTcqrLVfS9Cci5DaAdUjad8NzMQBoHywWIAFTA8Bl4p8cb7GqR9FcJYVsM6QlcjcGCZ5KhahgYOlBH5lw6bRMi48JzHrRWa1otXxmXprcLF4QiBKEZfKpHrSsszlCAKOKytlG7_xtNPRZ_UeZmeTRiyHWVDCcQSzM2W9U_7hfGa-BErmW20CNBitqWZmEkmGRci2KxP7cJceuTXjpYAcVWm1x4ZVN1_JtCisCU5egDoXIi8uFHwZigKhcBUBIS-AepvSKNdCA3HqeWzydKaRzM6Hd1iEyiOQZdz4pcGDrkcsbOgiUpCHGM_OPeIAPlZ8DqRjh6Wxa8O8YwyrfJZs6vLUcAjW-Jn5AaNpQFWU_VdbhTDQ";
		private static final String PRIV = "q_aDEMZpRAjbiqHwO23vKcgImYieSqUsCK7wWZEsq8Y";
		// the "pub" of the (different) HPKE-9 key pair from Appendix A.3
		private static final String OTHER_PUB = "ZEbKruTLTRJZf-UygOWQwuBNzChq8yuhGTVITLeU7emGD9tF9oFEy1BP9hmBRWo84Zyjr8xlvkadCNyu5iOfuoIC7pA5JCc3A7BNp2ZK8TnNPTsYJ9BTicjChlIMMYKVSnk9WjCj3EqM90RaRiSHYxMUJ0VV8fY_06BqrODCwNO_6BYGaaxHszSAVparmkEiSQOZwyB6xsc0dsU2MGVGANQDBCu3NSs2gZmN1fslWpxzqyN4YtZhwkozcmsGztObngYHXEtgqpo44mKqXHfMBIxjvsqgZ-vNzGyp04OErotG5QOeu5gQZquZ4TlS7JqxjjN0ktJ9Wqofvlq1i0JG97VL7aJ0IHJpnFl8-4cbqwq7-Wan_9U0fJux18PBDBq3jkQiwLiXZOk9Klgin6BGwpx-JPedIOOEEEnKLpQwg3lOZGuHfXGCT5BkGfk4sVVR3dg7uMvC4yFS5ftvggIWfMPI4LV-3DECG-pDe1vEpQFE5EwSBHUhpyjAWuMEHbpTKau5oGmVAIYXRKZfZ3CIFQV3gHoBZdZQoRhEXzKmdkPB2jJI16FnFGUK_GSZYsXK68IUk_lEnihTadnBEhM78-wh9ZtAXQsKgQtUdWR7nFt6yWAkSQIegmJzzkEw4_FBrNYUIXC930h1dYi1sZw5ZHo3dmY3Viq4pLiiixN9LrdzV6RGIwR8fmpqbqNAc_cVsFePATiHnwBQ5kej1BLMAkUfYhJpX1lV-9tloZLA6JdkRoAeXnEvIxyY1TUYpugYuZUeERwlWygVnOidsIi_Apo1KAUm-TocR6m0zGtG2YQ07mUeI2yqbctcg6EvYVVBLDu_RJeLFyAw-Xd_WXgWNoIzoOM5CXLOtDCcJwMoLJknW1dgNxdFZHG1mQg9T5wBMbEBpjK8a9oOnfxVblik3eUHYkS7TVhKSqCOuyOBzDQuVtHAt9Q6OCoOguqUmJeBV4GSd5IPSnpCendqBjEKZ2JTkNwFkuqqbmilEnYMHEOtMUyveWZi6_qm2kPG7aVcjFV9U4pXZEuRIJcugvJUH3qw9UQ7smgqsaJMFzrDVsAGQWItDJxcEOgBdBTAiit99igYmAeEyNoK-GQ46OYsNzq5-CuCiCGJZKNObWhddnROkmY6jFG7K_k_RgvAj_aW0oPIEzGz0jBtZqVDMTFHF6d4q9erpHOaO8h9e7k2nnrGyHgkJYOPQImVrLNc93OEJ1qLzUSwJaho8KqwNlOHqDuJgmKoSfEhqXQRfIh68qNqZ6SC9JYJ_-lwpKk_TQUYxJUdRkHB9fgkBwyoGsi0nLpOhMinsIc32CMyHMqvBsc9DlSgmZOBgiovynEtj_gqdVZ3ZYwDAaSaXTG7wLMyNwBfVycm5TdMQeZs8dwu6pifo_UYzBhj1EY8u3IdS3OVajDKZqkw9zeTacE2kwVsCkDOK_y-wQXEvyFCbAYW3IANbpAuIwpirGJfFTWHIFEm1CqL4FXPt8a9DusGHQCuq3bEkCtpnRiOTGOqgVSZSWkuoxbGnluihrRc5NYY87PCvMSRVxthHPS6-Af2yP_HWMkcfu3DwNyCFxBJgfvtXGLFSm8Zq6EG4zipdIVLeDl-Mg6s_8jDce27ki2xqXVQWA";

		private static String jwk(String alg, String pub, String priv) {
			return "{\"kty\":\"AKP\",\"alg\":\"" + alg + "\"" + (pub == null ? "" : ",\"pub\":\"" + pub + "\"") + (priv == null ? "" : ",\"priv\":\"" + priv + "\"") + "}";
		}

		@Test
		@DisplayName("a private JWK parses, exposes alg, and its pub matches the key derived from priv")
		void testValidPrivate() throws JoseParseException {
			var jwk = Assertions.assertInstanceOf(JWK.Private.class, JWK.parse(jwk("HPKE-9-KE", PUB, PRIV)));
			Assertions.assertEquals(Optional.of("HPKE-9-KE"), jwk.alg());
			Assertions.assertArrayEquals(Base64Url.decode(PUB), jwk.publicKey().getEncoded());
			Assertions.assertArrayEquals(Base64Url.decode(PRIV), jwk.privateKey().getEncoded());
			Assertions.assertEquals(jwk.toPublic(), JWK.parse(jwk("HPKE-9-KE", PUB, null)));
		}

		@Test
		@DisplayName("parsePrivate requires private material, parsePublic drops it")
		void testTypedParse() throws JoseParseException {
			var privateJwk = JWK.parsePrivate(jwk("HPKE-9-KE", PUB, PRIV));
			Assertions.assertEquals(privateJwk.toPublic(), JWK.parsePublic(jwk("HPKE-9-KE", PUB, PRIV)));
			Assertions.assertEquals(privateJwk.toPublic(), JWK.parsePublic(jwk("HPKE-9-KE", PUB, null)));
			var thrown = Assertions.assertThrows(JoseParseException.class, () -> JWK.parsePrivate(jwk("HPKE-9-KE", PUB, null)));
			Assertions.assertTrue(thrown.getMessage().contains("no private key material"));
			Assertions.assertThrows(JoseParseException.class, () -> JWK.parsePublic(jwk("HPKE-9-KE", OTHER_PUB, PRIV)), "private material is still validated");
		}

		@Test
		@DisplayName("a public JWK parses as JWK.Public")
		void testValidPublic() throws JoseParseException {
			var jwk = Assertions.assertInstanceOf(JWK.Public.class, JWK.parse(jwk("HPKE-9", PUB, null)));
			Assertions.assertArrayEquals(Base64Url.decode(PUB), jwk.publicKey().getEncoded());
		}

		static Stream<Arguments> invalidKeyMaterial() {
			var pub = Base64Url.decode(PUB);
			var flipped = pub.clone();
			flipped[100] ^= 0x01;
			return Stream.of(
					Arguments.of("pub missing (RFC 9964 Section 3: REQUIRED)", jwk("HPKE-9-KE", null, PRIV)),
					Arguments.of("pub missing on public JWK", jwk("HPKE-9-KE", null, null)),
					Arguments.of("pub too short", jwk("HPKE-9-KE", Base64Url.encode(Arrays.copyOf(pub, 1215)), null)),
					Arguments.of("pub too long", jwk("HPKE-9-KE", Base64Url.encode(Arrays.copyOf(pub, 1217)), null)),
					Arguments.of("pub of another key pair (RFC 9964 Section 7.4)", jwk("HPKE-9-KE", OTHER_PUB, PRIV)),
					Arguments.of("pub with one flipped bit", jwk("HPKE-9-KE", Base64Url.encode(flipped), PRIV)),
					Arguments.of("priv too short", jwk("HPKE-9-KE", PUB, Base64Url.encode(new byte[31]))),
					Arguments.of("priv too long", jwk("HPKE-9-KE", PUB, Base64Url.encode(new byte[33]))),
					Arguments.of("pub not a string", "{\"kty\":\"AKP\",\"alg\":\"HPKE-9-KE\",\"pub\":{},\"priv\":\"" + PRIV + "\"}"),
					Arguments.of("priv not a string", "{\"kty\":\"AKP\",\"alg\":\"HPKE-9-KE\",\"pub\":\"" + PUB + "\",\"priv\":{}}")
			);
		}

		@ParameterizedTest(name = "{0}")
		@MethodSource("invalidKeyMaterial")
		@DisplayName("missing, malformed or mismatched pub/priv is rejected")
		void testInvalidKeyMaterial(String name, String json) {
			Assertions.assertThrows(JoseParseException.class, () -> JWK.parse(json));
		}

		@ParameterizedTest(name = "alg = {0}")
		@ValueSource(strings = {"HPKE-90", "HPKE-9-KE-", "hpke-9", "HPKE-0", "ECDH-ES+A256KW", ""})
		@DisplayName("alg must be exactly HPKE-9 or HPKE-9-KE")
		void testInvalidAlg(String alg) {
			var thrown = Assertions.assertThrows(JoseParseException.class, () -> JWK.parse(jwk(alg, PUB, PRIV)));
			Assertions.assertTrue(thrown.getMessage().contains("Unsupported AKP algorithm"), thrown.getMessage());
		}

		@Test
		@DisplayName("alg, if present, must be a string")
		void testNonStringAlg() {
			Assertions.assertThrows(JoseParseException.class, () -> JWK.parse("{\"kty\":\"AKP\",\"alg\":{},\"pub\":\"" + PUB + "\",\"priv\":\"" + PRIV + "\"}"));
		}

		@Test
		@DisplayName("Alg factories bind the JWK to the mode named by its alg")
		void testAlgBinding() throws JoseParseException {
			var ke = JWK.parsePrivate(jwk("HPKE-9-KE", PUB, PRIV));
			var integrated = JWK.parsePrivate(jwk("HPKE-9", PUB, PRIV));

			Assertions.assertDoesNotThrow(() -> Alg.hpke9Ke(ke));
			Assertions.assertDoesNotThrow(() -> Alg.hpke9Ke(ke.toPublic()));
			Assertions.assertDoesNotThrow(() -> Alg.hpke9(integrated));
			Assertions.assertThrows(IllegalArgumentException.class, () -> Alg.hpke9(ke));
			Assertions.assertThrows(IllegalArgumentException.class, () -> Alg.hpke9(ke.toPublic()));
			Assertions.assertThrows(IllegalArgumentException.class, () -> Alg.hpke9Ke(integrated));
			Assertions.assertThrows(IllegalArgumentException.class, () -> Alg.hpke9Ke(integrated.toPublic()));
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
			Assertions.assertInstanceOf(ECPublicKey.class, Assertions.assertInstanceOf(JWK.Public.class, JWK.parse(jwk(X, Y, null))).publicKey());
			Assertions.assertInstanceOf(ECPrivateKey.class, Assertions.assertInstanceOf(JWK.Private.class, JWK.parse(jwk(X, Y, D))).privateKey());
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
			Assertions.assertInstanceOf(JWK.Private.class, JWK.parse(jwk(X, Y, nMinusOne)));
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
		Assertions.assertThrows(JoseParseException.class, () -> JWK.parse("{\"kty\":\"EC\",\"crv\":\"P-256\",\"d\":\"" + "AA".repeat(32) + "\"}")); // RFC 7518 Section 6.2.2: x and y are required alongside d
	}
}
