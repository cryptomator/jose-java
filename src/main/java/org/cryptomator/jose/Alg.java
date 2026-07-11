package org.cryptomator.jose;

import org.cryptomator.jose.alg.EcdhEsAlg;
import org.cryptomator.jose.alg.HPKEKeyEncryptionAlg;
import org.cryptomator.jose.alg.Pbes2Alg;
import org.cryptomator.jose.hpke.HPKE;
import org.cryptomator.jose.hpke.XwingProvider;
import org.cryptomator.jose.util.Curve;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/// CEK encryption algorithm as defined in [RFC 7518 Section 4.1](https://www.rfc-editor.org/rfc/rfc7518#section-4.1)
public sealed interface Alg permits DecryptionAlg, EncryptionAlg {

	///  `alg` values as defined in [RFC 7518 Section 4.1](https://www.rfc-editor.org/rfc/rfc7518#section-4.1)
	String name();

	// FACTORY METHODS

	// TODO: which algorithms do we want to expose here?

	static EncryptionAlg pbes2(char[] password, int iterationCount) {
		return new Pbes2Alg(Pbes2Alg.Type.PBES2_HS512_A256KW, password, iterationCount);
	}

	static DecryptionAlg pbes2(char[] password) {
		return new Pbes2Alg(Pbes2Alg.Type.PBES2_HS512_A256KW, password, 0);
	}

	static DecryptionAlg ecdhEs(PrivateKey privateKey) {
		if (!(privateKey instanceof ECPrivateKey k)) {
			throw new IllegalArgumentException("Private key must be an instance of ECPrivateKey");
		}
		return new EcdhEsAlg(EcdhEsAlg.Type.ECDH_ES_A256KW, Curve.P384,null, k);
	}

	static EncryptionAlg ecdhEs(PublicKey publicKey) {
		if (!(publicKey instanceof ECPublicKey k)) {
			throw new IllegalArgumentException("Public key must be an instance of ECPublicKey");
		}
		return new EcdhEsAlg(EcdhEsAlg.Type.ECDH_ES_A256KW, Curve.P384, k, null);
	}

	/// Key Encryption with `HPKE-2-KE`, as defined in [draft-ietf-jose-hpke-encrypt, Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6)
	static EncryptionAlg hpke2Ke(PublicKey publicKey) {
		if (!(publicKey instanceof ECPublicKey k)) {
			throw new IllegalArgumentException("Public key must be an instance of ECPublicKey");
		}
		return new HPKEKeyEncryptionAlg(HPKE.hpke2(), Curve.P521.ensureSameCurve(k), null);
	}

	/// Key Encryption with `HPKE-2-KE`, as defined in [draft-ietf-jose-hpke-encrypt, Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6)
	static DecryptionAlg hpke2Ke(PrivateKey privateKey) {
		if (!(privateKey instanceof ECPrivateKey k)) {
			throw new IllegalArgumentException("Private key must be an instance of ECPrivateKey");
		}
		return new HPKEKeyEncryptionAlg(HPKE.hpke2(), null, Curve.P521.ensureSameCurve(k));
	}

	/// Key Encryption with `HPKE-9-KE`, as defined in [draft-ietf-jose-hpke-pq-pqt](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-pq-pqt/)
	static EncryptionAlg hpke9Ke(PublicKey publicKey) {
		return new HPKEKeyEncryptionAlg(HPKE.hpke9(), asXwingPublicKey(publicKey), null);
	}

	/// Key Encryption with `HPKE-9-KE`, as defined in [draft-ietf-jose-hpke-pq-pqt](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-pq-pqt/)
	static DecryptionAlg hpke9Ke(PrivateKey privateKey) {
		return new HPKEKeyEncryptionAlg(HPKE.hpke9(), null, asXwingPrivateKey(privateKey));
	}

	private static PublicKey asXwingPublicKey(PublicKey publicKey) {
		try {
			var kf = KeyFactory.getInstance("X-Wing", XwingProvider.INSTANCE);
			return (PublicKey) kf.translateKey(publicKey);
		} catch (NoSuchAlgorithmException e) {
			throw new AssertionError("Custom X-Wing provider must support X-Wing key factory", e);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Not an X-Wing public key.", e);
		}
	}

	private static PrivateKey asXwingPrivateKey(PrivateKey privateKey) {
		try {
			var kf = KeyFactory.getInstance("X-Wing", XwingProvider.INSTANCE);
			return (PrivateKey) kf.translateKey(privateKey);
		} catch (NoSuchAlgorithmException e) {
			throw new AssertionError("Custom X-Wing provider must support X-Wing key factory", e);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Not an X-Wing private key.", e);
		}
	}

}
