package org.cryptomator.jose;

import com.google.gson.JsonObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cryptomator.jose.alg.EcdhEsAlg;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

class EcdhEsAlgTest {

	private static KeyPair generate(String jcaCurve) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		var gen = KeyPairGenerator.getInstance("EC");
		gen.initialize(new ECGenParameterSpec(jcaCurve));
		return gen.generateKeyPair();
	}

	@ParameterizedTest
	@ValueSource(strings = {"secp256r1", "secp384r1", "secp521r1"})
	@DisplayName("ecdhEs accepts P-256, P-384 and P-521 key pairs and round-trips on them")
	void testSupportedCurves(String jcaCurve) throws Exception {
		var kp = generate(jcaCurve);
		var encrypted = JWE.build("payload").encrypt(Enc.A256GCM, Alg.ecdhEs(kp.getPublic())).toCompactSerialization();
		Assertions.assertEquals("payload", JWE.parse(encrypted).decrypt(Alg.ecdhEs(kp.getPrivate())).payload());
	}

	@Test
	@DisplayName("ecdhEs rejects a key on an unsupported curve")
	void testUnsupportedCurve() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		var gen = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider()); // SunEC no longer ships secp256k1
		gen.initialize(new ECGenParameterSpec("secp256k1"));
		var kp = gen.generateKeyPair();
		Assertions.assertThrows(IllegalArgumentException.class, () -> Alg.ecdhEs(kp.getPublic()));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Alg.ecdhEs(kp.getPrivate()));
	}

	@Test
	@DisplayName("a recipient on another curve than the epk is skipped, not fatal")
	void testCurveMismatchIsSkipped() throws Exception {
		var p256 = generate("secp256r1");
		var p384 = generate("secp384r1");
		var encrypted = JWE.build("payload").encrypt(Enc.A256GCM, Alg.ecdhEs(p256.getPublic())).toCompactSerialization();
		var parsed = JWE.parse(encrypted);

		var thrown = Assertions.assertThrows(JoseDecryptException.class, () -> parsed.decrypt(Alg.ecdhEs(p384.getPrivate())));
		Assertions.assertEquals(1, thrown.getSuppressed().length);
		Assertions.assertTrue(thrown.getSuppressed()[0].getMessage().contains("curve"));
		// and a later matching candidate still succeeds:
		Assertions.assertEquals("payload", parsed.decrypt(Alg.ecdhEs(p384.getPrivate()), Alg.ecdhEs(p256.getPrivate())).payload());
	}

	@Nested
	@DisplayName("deriveKey (Concat KDF)")
	class DeriveKey {

		// apu/apv are base64url-encoded per RFC 7518 §4.6.1.2/§4.6.1.3
		private static final String APU = "QWxpY2U"; // "Alice"
		private static final String APV = "Qm9i";    // "Bob"
		private static final byte[] SHARED_SECRET = "shared-secret-placeholder-000000".getBytes(StandardCharsets.US_ASCII);

		private final EcdhEsAlg alg = new EcdhEsAlg(EcdhEsAlg.Type.ECDH_ES_A256KW, null, null, null);

		private static JsonObject header(String apu, String apv) {
			var header = new JsonObject();
			if (apu != null) {
				header.addProperty("apu", apu);
			}
			if (apv != null) {
				header.addProperty("apv", apv);
			}
			return header;
		}

		@Test
		@DisplayName("matches the RFC 7518 Appendix C example (direct ECDH-ES with A128GCM)")
		void testRfc7518AppendixC() {
			var z = new byte[]{(byte) 158, (byte) 86, (byte) 217, (byte) 29, (byte) 129, (byte) 113, (byte) 53, (byte) 211, (byte) 114, (byte) 131, (byte) 66, (byte) 131, (byte) 191, (byte) 132, (byte) 38, (byte) 156, (byte) 251, (byte) 49, (byte) 110, (byte) 163, (byte) 218, (byte) 128, (byte) 106, (byte) 72, (byte) 246, (byte) 218, (byte) 167, (byte) 121, (byte) 140, (byte) 254, (byte) 144, (byte) 196};
			var derived = EcdhEsAlg.deriveKey(z, "A128GCM", 16, header(APU, APV));
			Assertions.assertEquals("VqqN6vgjbSBcIijNcacQGg", Base64.getUrlEncoder().withoutPadding().encodeToString(derived));
		}

		@Test
		@DisplayName("apv is bound into the derived key (regression: apv must not read apu)")
		void testApvInfluencesDerivedKey() {
			// two headers differing only in apv: if apv were ignored (the bug), these would be identical
			var withApvBob = alg.deriveKey(SHARED_SECRET, header(APU, APV));
			var withApvAlice = alg.deriveKey(SHARED_SECRET, header(APU, APU));

			Assertions.assertFalse(Arrays.equals(withApvBob, withApvAlice));
		}

		@Test
		@DisplayName("apu and apv occupy distinct OtherInfo fields (swapping them changes the derived key)")
		void testApuApvNotInterchangeable() {
			var normal = alg.deriveKey(SHARED_SECRET, header(APU, APV));
			var swapped = alg.deriveKey(SHARED_SECRET, header(APV, APU));

			Assertions.assertFalse(Arrays.equals(normal, swapped));
		}

		@Test
		@DisplayName("apu is bound into the derived key")
		void testApuInfluencesDerivedKey() {
			var withApuAlice = alg.deriveKey(SHARED_SECRET, header(APU, APV));
			var withApuBob = alg.deriveKey(SHARED_SECRET, header(APV, APV));

			Assertions.assertFalse(Arrays.equals(withApuAlice, withApuBob));
		}

		@Test
		@DisplayName("a non-base64url apu is rejected")
		void testMalformedApu() {
			Assertions.assertThrows(IllegalArgumentException.class, () -> alg.deriveKey(SHARED_SECRET, header("not base64url!", APV)));
		}

		@Test
		@DisplayName("a non-string apv is rejected")
		void testNonStringApv() {
			var header = header(APU, null);
			header.addProperty("apv", 42);
			Assertions.assertThrows(IllegalArgumentException.class, () -> alg.deriveKey(SHARED_SECRET, header));
		}
	}
}
