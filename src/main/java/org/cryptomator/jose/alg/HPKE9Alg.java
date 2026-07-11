package org.cryptomator.jose.alg;

import org.cryptomator.jose.hpke.AEAD;
import org.cryptomator.jose.hpke.Shake;
import org.cryptomator.jose.hpke.XwingProvider;

import javax.crypto.KEM;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

/// PQ/T hybrid HPKE using the MLKEM768-X25519 KEM (a.k.a. X-Wing), SHAKE256 KDF, and AES-256-GCM AEAD, as registered in
/// [draft-ietf-jose-hpke-pq-pqt](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-pq-pqt/)
public final class HPKE9Alg extends HPKEAlg {

	public HPKE9Alg(PublicKey publicKey, PrivateKey privateKey) {
		super(kem(), Shake.SHAKE256, AEAD.AES256GCM, publicKey, privateKey);
	}

	private static KEM kem() {
		try {
			return KEM.getInstance("X-Wing", XwingProvider.INSTANCE);
		} catch (NoSuchAlgorithmException e) {
			throw new AssertionError("Custom X-Wing provider must support X-Wing KEM", e);
		}
	}

	@Override
	public String name() {
		return "HPKE-9";
	}

	@Override
	protected byte[] hpkeSuiteId() {
		// https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05 (MLKEM768-X25519, SHAKE256), https://www.iana.org/assignments/hpke/hpke.xhtml
		return new byte[] {
				'H', 'P', 'K', 'E', //
				0x64, 0x7a, // KEM ID
				0x00, 0x11, // KDF ID
				0x00, 0x02  // AEAD ID
		};
	}
}
