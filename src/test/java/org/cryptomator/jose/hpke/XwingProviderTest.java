package org.cryptomator.jose.hpke;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.KEM;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

class XwingProviderTest {

	@Test
	void provideKeyPairGenerator() throws NoSuchAlgorithmException {
		var keyPairGenerator = KeyPairGenerator.getInstance("X-Wing", XwingProvider.INSTANCE);

		Assertions.assertInstanceOf(KeyPairGenerator.class, keyPairGenerator);
	}

	@Test
	void provideKeyFactory() throws NoSuchAlgorithmException {
		var keyFactory = KeyFactory.getInstance("X-Wing", XwingProvider.INSTANCE);

		Assertions.assertInstanceOf(KeyFactory.class, keyFactory);
	}

	@Test
	void provideKem() throws NoSuchAlgorithmException {
		var kem = KEM.getInstance("X-Wing", XwingProvider.INSTANCE);

		Assertions.assertInstanceOf(KEM.class, kem);
	}

}