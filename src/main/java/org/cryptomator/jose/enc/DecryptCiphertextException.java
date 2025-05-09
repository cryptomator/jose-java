package org.cryptomator.jose.enc;

import org.cryptomator.jose.JoseDecryptException;

public final class DecryptCiphertextException extends JoseDecryptException {

	public DecryptCiphertextException(String message, Throwable cause) {
		super(message, cause);
	}

}
