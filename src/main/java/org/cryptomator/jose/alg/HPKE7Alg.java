package org.cryptomator.jose.alg;

import org.cryptomator.jose.hpke.AEAD;
import org.cryptomator.jose.hpke.HKDF;
import org.cryptomator.jose.hpke.XwingProvider;

import javax.crypto.KEM;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public final class HPKE7Alg extends HPKEAlg {

	public HPKE7Alg(PublicKey publicKey, PrivateKey privateKey) {
		super(kem(), HKDF.sha256(), AEAD.AES256GCM, publicKey, privateKey);
	}

	private static KEM kem() {
		try {
			return KEM.getInstance("X-Wing", XwingProvider.INSTANCE);
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("JVM does not support DHKEM", e);
		}
	}

	@Override
	public String name() {
		return "HPKE-7";
	}

	@Override
	protected byte[] hpkeSuiteId() {
		// https://www.iana.org/assignments/hpke/hpke.xhtml
		return new byte[] {
				'H', 'P', 'K', 'E', //
				0x64, 0x7a, // KEM ID
				0x00, 0x01, // KDF ID
				0x00, 0x02  // AEAD ID
		};
	}
}
