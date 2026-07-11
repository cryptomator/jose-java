package org.cryptomator.jose;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

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
}
