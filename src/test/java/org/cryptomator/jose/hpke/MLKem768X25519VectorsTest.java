package org.cryptomator.jose.hpke;

import org.cryptomator.jose.util.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.mockito.Mockito;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/// Verifies that the X-Wing implementation is the `MLKEM768-X25519` hybrid KEM from
/// [draft-irtf-cfrg-concrete-hybrid-kems, Section 4.2](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-concrete-hybrid-kems-04#section-4.2)
/// (which is defined to be identical to X-Wing), using the test vectors from
/// [Appendix B.2](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-concrete-hybrid-kems-04#appendix-B.2).
class MLKem768X25519VectorsTest {

	private static final String VECTORS = "/draft-irtf-cfrg-concrete-hybrid-kems-04-mlkem768-x25519.csv";

	@ParameterizedTest
	@CsvFileSource(resources = VECTORS, numLinesToSkip = 1)
	void testKeyGeneration(@Hex byte[] seed, @Hex byte[] randomness, @Hex byte[] encapsulationKey, @Hex byte[] ciphertext, @Hex byte[] sharedSecret) {
		var keyPair = XwingKeyPairGeneratorSpi.generateKeyPairDerand(seed);

		Assertions.assertArrayEquals(encapsulationKey, keyPair.getPublic().getEncoded());
		Assertions.assertArrayEquals(seed, keyPair.getPrivate().getEncoded());
	}

	@ParameterizedTest
	@CsvFileSource(resources = VECTORS, numLinesToSkip = 1)
	void testEncapsulateDerand(@Hex byte[] seed, @Hex byte[] randomness, @Hex byte[] encapsulationKey, @Hex byte[] ciphertext, @Hex byte[] sharedSecret) throws NoSuchAlgorithmException, InvalidKeyException {
		var publicKey = new XwingPublicKey(encapsulationKey);
		var random = Mockito.mock(SecureRandom.class);
		Mockito.doAnswer(invocation -> {
			byte[] bytes = invocation.getArgument(0);
			Assertions.assertEquals(32, bytes.length);
			System.arraycopy(randomness, 0, bytes, 0, 32);
			return null;
		}).doAnswer(invocation -> {
			byte[] bytes = invocation.getArgument(0);
			Assertions.assertEquals(32, bytes.length);
			System.arraycopy(randomness, 32, bytes, 0, 32);
			return null;
		}).when(random).nextBytes(Mockito.any());

		var kem = KEM.getInstance("X-Wing", XwingProvider.INSTANCE);
		var encapsulated = kem.newEncapsulator(publicKey, random).encapsulate();

		Assertions.assertArrayEquals(ciphertext, encapsulated.encapsulation());
		Assertions.assertArrayEquals(sharedSecret, encapsulated.key().getEncoded());
	}

	@ParameterizedTest
	@CsvFileSource(resources = VECTORS, numLinesToSkip = 1)
	void testDecapsulate(@Hex byte[] seed, @Hex byte[] randomness, @Hex byte[] encapsulationKey, @Hex byte[] ciphertext, @Hex byte[] sharedSecret) throws NoSuchAlgorithmException, InvalidKeyException, DecapsulateException {
		var privateKey = new XwingPrivateKey(seed);

		var kem = KEM.getInstance("X-Wing", XwingProvider.INSTANCE);
		var decapsulated = kem.newDecapsulator(privateKey).decapsulate(ciphertext);

		Assertions.assertArrayEquals(sharedSecret, decapsulated.getEncoded());
	}

}
