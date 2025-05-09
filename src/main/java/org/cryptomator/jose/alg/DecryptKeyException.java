package org.cryptomator.jose.alg;

import org.cryptomator.jose.JoseDecryptException;

public final class DecryptKeyException extends JoseDecryptException {

	public DecryptKeyException(String message, Throwable cause) {
		super(message, cause);
	}

}
