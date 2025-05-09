package org.cryptomator.jose;

public class JoseParseException extends JoseException {

	public JoseParseException(String message) {
		super(message);
	}

	public JoseParseException(String message, Throwable cause) {
		super(message, cause);
	}

}
