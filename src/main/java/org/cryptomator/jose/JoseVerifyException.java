package org.cryptomator.jose;

/// A JWS could not be verified: no provided algorithm matches, or the signature is invalid.
public class JoseVerifyException extends JoseException {

	public JoseVerifyException(String message) {
		super(message);
	}

	public JoseVerifyException(String message, Throwable cause) {
		super(message, cause);
	}

}
