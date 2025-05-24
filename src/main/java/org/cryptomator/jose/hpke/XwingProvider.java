package org.cryptomator.jose.hpke;

import java.security.Provider;

public final class XwingProvider extends Provider {

	public static final String NAME = "X-Wing";

	public static final Provider INSTANCE = new XwingProvider();

	public XwingProvider() {
		super(NAME, "1.0","Provides X-Wing KEM");
		// putService(Service);
		put("KeyPairGenerator.X-Wing", XwingKeyPairGeneratorSpi.class.getName());
		put("KEM.X-Wing", XwingKEMSpi.class.getName());
	}

}
