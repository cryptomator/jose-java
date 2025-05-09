package org.cryptomator.jose.enc;

import org.cryptomator.jose.JoseDecryptException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class A256GCMTest {

	// FIXME: add official test vectors in parameterized test

	@Test
	public void encryptAndDecrypt() throws JoseDecryptException {
		var alg = new A256GCM();

		var cek = alg.generateCek();
		var iv = alg.generateIv();
		var aad = new byte[0];
		var plaintext = "Hello World".getBytes();

		var ciphertext = alg.encrypt(cek, iv, aad, plaintext);

		var decrypted = alg.decrypt(cek, iv, aad, ciphertext.ciphertext(), ciphertext.tag());
		Assertions.assertArrayEquals(plaintext, decrypted);
	}

}