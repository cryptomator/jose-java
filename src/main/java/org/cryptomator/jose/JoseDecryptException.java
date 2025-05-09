package org.cryptomator.jose;

import org.cryptomator.jose.alg.DecryptKeyException;
import org.cryptomator.jose.enc.DecryptCiphertextException;

public sealed class JoseDecryptException extends JoseException permits DecryptKeyException, DecryptCiphertextException {

	public JoseDecryptException(String message) {
		super(message);
	}

	public JoseDecryptException(String message, Throwable cause) {
		super(message, cause);
	}
}
