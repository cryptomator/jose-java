package org.cryptomator.jose;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class JWEIntegrationTest {

	@Test
	@DisplayName("Encrypt and decrypt with PBES2")
	public void testEncryptAndDecrypt() throws JoseException {
		// given
		var encryptedJWE = JWE.build("payload").encrypt(Enc.A256GCM, Alg.pbes2("secret".toCharArray(), 10));

		var json = encryptedJWE.toJsonSerialization();
		var flattened = encryptedJWE.toFlattenedJsonSerialization();
		var compact = encryptedJWE.toCompactSerialization();

		// when
		var decrypted1 = JWE.parse(json).decrypt(Alg.pbes2("wrong".toCharArray()), Alg.pbes2("secret".toCharArray()));
		var decrypted2 = JWE.parse(flattened).decrypt(Alg.pbes2("wrong".toCharArray()), Alg.pbes2("secret".toCharArray()));
		var decrypted3 = JWE.parse(compact).decrypt(Alg.pbes2("wrong".toCharArray()), Alg.pbes2("secret".toCharArray()));

		// then
		Assertions.assertEquals("payload", decrypted1.payload());
		Assertions.assertEquals("payload", decrypted2.payload());
		Assertions.assertEquals("payload", decrypted3.payload());
	}

}