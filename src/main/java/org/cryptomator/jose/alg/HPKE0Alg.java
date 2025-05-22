package org.cryptomator.jose.alg;

import org.cryptomator.jose.hpke.AEAD;
import org.cryptomator.jose.hpke.HKDF;
import org.cryptomator.jose.util.Curve;

import javax.crypto.KEM;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public final class HPKE0Alg extends HPKEAlg {

	public HPKE0Alg(ECPublicKey publicKey, ECPrivateKey privateKey) {
		super(kem(), HKDF.sha256(), AEAD.AES128GCM, Curve.P256.ensureSameCurve(publicKey), Curve.P256.ensureSameCurve(privateKey));
	}

	private static KEM kem() {
		try {
			return KEM.getInstance("DHKEM");
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("JVM does not support DHKEM", e);
		}
	}

	@Override
	public String name() {
		return "HPKE-0";
	}

	@Override
	protected byte[] hpkeSuiteId() {
		// https://www.iana.org/assignments/hpke/hpke.xhtml
		return new byte[] {
				'H', 'P', 'K', 'E', //
				0x00, 0x10, // KEM ID
				0x00, 0x01, // KDF ID
				0x00, 0x01  // AEAD ID
		};
	}
}
