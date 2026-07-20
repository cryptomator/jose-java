package org.cryptomator.jose;

import com.google.gson.JsonObject;
import org.cryptomator.jose.alg.EcdhEsAlg;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

class EcdhEsAlgTest {

	private static KeyPair generate(String jcaCurve) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		var gen = KeyPairGenerator.getInstance("EC");
		gen.initialize(new ECGenParameterSpec(jcaCurve));
		return gen.generateKeyPair();
	}

	@Test
	@DisplayName("ecdhEs accepts a P-384 key pair")
	void testCorrectCurve() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		var kp = generate("secp384r1");
		Assertions.assertDoesNotThrow(() -> Alg.ecdhEs(kp.getPublic()));
		Assertions.assertDoesNotThrow(() -> Alg.ecdhEs(kp.getPrivate()));
	}

	@Test
	@DisplayName("ecdhEs rejects a wrong-curve public key")
	void testWrongCurvePublicKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		var kp = generate("secp256r1"); // ecdhEs expects P-384
		Assertions.assertThrows(IllegalArgumentException.class, () -> Alg.ecdhEs(kp.getPublic()));
	}

	@Test
	@DisplayName("ecdhEs rejects a wrong-curve private key")
	void testWrongCurvePrivateKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		var kp = generate("secp256r1"); // ecdhEs expects P-384
		Assertions.assertThrows(IllegalArgumentException.class, () -> Alg.ecdhEs(kp.getPrivate()));
	}

	@Nested
	@DisplayName("deriveKey binds the apu/apv ConcatKDF OtherInfo fields")
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
	}
}
