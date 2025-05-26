package org.cryptomator.jose.hpke;

import java.security.PrivateKey;
import java.util.Arrays;

class XwingPrivateKey implements PrivateKey {

	private final byte[] sk;

	public XwingPrivateKey(byte[] sk) {
		if (sk == null || sk.length != 32) {
			throw new IllegalArgumentException("Private key must be 32 bytes long");
		}
		this.sk = Arrays.copyOf(sk, sk.length);
	}

	@Override
	public String getAlgorithm() {
		return "X-Wing";
	}

	@Override
	public String getFormat() {
		return "RAW";
	}

	@Override
	public byte[] getEncoded() {
		return sk.clone();
	}

	@Override
	public void destroy() {
		Arrays.fill(sk, (byte) 0);
	}

}
