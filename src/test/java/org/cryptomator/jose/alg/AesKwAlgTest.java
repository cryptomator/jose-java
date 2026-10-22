package org.cryptomator.jose.alg;

import com.google.gson.JsonParser;
import org.cryptomator.jose.Alg;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.JWE;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.JoseException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.util.HexFormat;

class AesKwAlgTest {

	// test vector from RFC 3394, Section 4.6 (256-bit KEK, 256-bit key data)
	private static final byte[] KEK = HexFormat.of().parseHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
	private static final byte[] KEY_DATA = HexFormat.of().parseHex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
	private static final byte[] WRAPPED = HexFormat.of().parseHex("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21");

	@Nested
	@DisplayName("AesKw")
	class AesKwTest {

		@Test
		@DisplayName("wrap matches RFC 3394 Section 4.6")
		void wrap() {
			Assertions.assertArrayEquals(WRAPPED, AesKw.wrap(new SecretKeySpec(KEK, "AES"), KEY_DATA));
		}

		@Test
		@DisplayName("unwrap matches RFC 3394 Section 4.6")
		void unwrap() throws DecryptKeyException {
			Assertions.assertArrayEquals(KEY_DATA, AesKw.unwrap(new SecretKeySpec(KEK, "AES"), WRAPPED));
		}

		@Test
		@DisplayName("unwrap with the wrong KEK fails the integrity check")
		void unwrapWrongKek() {
			var wrongKek = KEK.clone();
			wrongKek[0] ^= 0x01;
			Assertions.assertThrows(DecryptKeyException.class, () -> AesKw.unwrap(new SecretKeySpec(wrongKek, "AES"), WRAPPED));
		}

		@Test
		@DisplayName("unwrap rejects a wrapped key of invalid length")
		void unwrapInvalidLength() {
			var truncated = java.util.Arrays.copyOf(WRAPPED, WRAPPED.length - 1);
			Assertions.assertThrows(DecryptKeyException.class, () -> AesKw.unwrap(new SecretKeySpec(KEK, "AES"), truncated));
		}

	}

	@Nested
	@DisplayName("A256KW")
	class A256Kw {

		@Test
		@DisplayName("rejects a non-AES key")
		void rejectNonAesKey() {
			Assertions.assertThrows(IllegalArgumentException.class, () -> Alg.a256kw(new SecretKeySpec(KEK, "HmacSHA256")));
		}

		@Test
		@DisplayName("rejects a 128-bit key")
		void rejectShortKey() {
			Assertions.assertThrows(IllegalArgumentException.class, () -> Alg.a256kw(new SecretKeySpec(KEK, 0, 16, "AES")));
		}

		@Test
		@DisplayName("encrypt and decrypt, compact serialization")
		void roundTripCompact() throws JoseException {
			var alg = Alg.a256kw(new SecretKeySpec(KEK, "AES"));
			var jwe = JWE.build("payload").encrypt(Enc.A256GCM, alg).toCompactSerialization();
			var decrypted = JWE.parse(jwe).decrypt(alg);
			Assertions.assertEquals("payload", decrypted.payload());
			Assertions.assertEquals("A256KW", decrypted.protectedHeader().get("alg").getAsString());
		}

		@Test
		@DisplayName("encrypt and decrypt, general JSON serialization with two A256KW recipients")
		void roundTripTwoRecipients() throws JoseException {
			var kek1 = Alg.a256kw(new SecretKeySpec(KEK, "AES"));
			var otherKek = KEK.clone();
			otherKek[31] ^= 0x01;
			var kek2 = Alg.a256kw(new SecretKeySpec(otherKek, "AES"));
			var jwe = JWE.build("payload").encrypt(Enc.A128GCM, kek1, kek2).toJsonSerialization();

			Assertions.assertEquals(2, JsonParser.parseString(jwe).getAsJsonObject().getAsJsonArray("recipients").size());
			Assertions.assertEquals("payload", JWE.parse(jwe).decrypt(kek1).payload());
			Assertions.assertEquals("payload", JWE.parse(jwe).decrypt(kek2).payload()); // the first recipient's integrity check fails and is skipped
		}

		@Test
		@DisplayName("wrong KEK is reported as a key decryption failure")
		void wrongKek() throws JoseException {
			var jwe = JWE.build("payload").encrypt(Enc.A256GCM, Alg.a256kw(new SecretKeySpec(KEK, "AES"))).toCompactSerialization();
			var wrongKek = KEK.clone();
			wrongKek[0] ^= 0x01;
			var parsed = JWE.parse(jwe);
			var thrown = Assertions.assertThrows(JoseDecryptException.class, () -> parsed.decrypt(Alg.a256kw(new SecretKeySpec(wrongKek, "AES"))));
			Assertions.assertEquals(1, thrown.getSuppressed().length);
			Assertions.assertInstanceOf(DecryptKeyException.class, thrown.getSuppressed()[0]);
		}

	}

}
