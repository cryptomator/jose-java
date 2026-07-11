package org.cryptomator.jose.alg;

import org.cryptomator.jose.hpke.AEAD;
import org.cryptomator.jose.hpke.HKDF;
import org.cryptomator.jose.util.Curve;

import javax.crypto.KEM;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public final class HPKE1Alg extends HPKEAlg {

	public HPKE1Alg(ECPublicKey publicKey, ECPrivateKey privateKey) {
		super(kem(), HKDF.sha384(), AEAD.AES256GCM, Curve.P384.ensureSameCurve(publicKey), Curve.P384.ensureSameCurve(privateKey));
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
		return "HPKE-1";
	}

	@Override
	protected byte[] hpkeSuiteId() {
		// https://www.iana.org/assignments/hpke/hpke.xhtml
		return new byte[] {
				'H', 'P', 'K', 'E', //
				0x00, 0x11, // KEM ID
				0x00, 0x02, // KDF ID
				0x00, 0x02  // AEAD ID
		};
	}
}
