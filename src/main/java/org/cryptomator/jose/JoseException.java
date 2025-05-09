package org.cryptomator.jose;

public class JoseException extends Exception {

	public JoseException(String message) {
		super(message);
	}

	public JoseException(String message, Throwable cause) {
		super(message, cause);
	}

	public JoseException(Throwable cause) {
		super(cause);
	}
}
