package org.cryptomator.jose;

import org.cryptomator.jose.alg.EcdhEsAlg;
import org.cryptomator.jose.alg.HPKEIntegratedAlg;
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

/// A JWE algorithm, identified by its `alg` header value. It is split by direction into [EncryptionAlg] and [DecryptionAlg], and by JWE Key Management Mode
/// into key management (protecting a content encryption key, [RFC 7518 Section 4](https://www.rfc-editor.org/rfc/rfc7518#section-4)) and Integrated Encryption
/// ([draft-ietf-jose-hpke-encrypt Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5), where HPKE encrypts the payload directly and there is no CEK).
public sealed interface Alg permits DecryptionAlg, EncryptionAlg {

	/// The `alg` (algorithm) header parameter value identifying this algorithm.
	String name();

	// FACTORY METHODS

	// TODO: which algorithms do we want to expose here?

	static KeyEncryptionAlg pbes2(char[] password, int iterationCount) {
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

	static KeyEncryptionAlg ecdhEs(PublicKey publicKey) {
		if (!(publicKey instanceof ECPublicKey k)) {
			throw new IllegalArgumentException("Public key must be an instance of ECPublicKey");
		}
		return new EcdhEsAlg(EcdhEsAlg.Type.ECDH_ES_A256KW, Curve.P384, k, null);
	}

	/// Integrated Encryption with `HPKE-0`, as defined in [draft-ietf-jose-hpke-encrypt, Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5)
	static IntegratedEncryptionAlg hpke0(PublicKey publicKey) {
		if (!(publicKey instanceof ECPublicKey k)) {
			throw new IllegalArgumentException("Public key must be an instance of ECPublicKey");
		}
		return new HPKEIntegratedAlg(HPKE.hpke0(), Curve.P256.ensureSameCurve(k), null);
	}

	/// Integrated Encryption with `HPKE-0`, as defined in [draft-ietf-jose-hpke-encrypt, Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5)
	static DecryptionAlg hpke0(PrivateKey privateKey) {
		if (!(privateKey instanceof ECPrivateKey k)) {
			throw new IllegalArgumentException("Private key must be an instance of ECPrivateKey");
		}
		return new HPKEIntegratedAlg(HPKE.hpke0(), null, Curve.P256.ensureSameCurve(k));
	}

	/// Integrated Encryption with `HPKE-1`, as defined in [draft-ietf-jose-hpke-encrypt, Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5)
	static IntegratedEncryptionAlg hpke1(PublicKey publicKey) {
		if (!(publicKey instanceof ECPublicKey k)) {
			throw new IllegalArgumentException("Public key must be an instance of ECPublicKey");
		}
		return new HPKEIntegratedAlg(HPKE.hpke1(), Curve.P384.ensureSameCurve(k), null);
	}

	/// Integrated Encryption with `HPKE-1`, as defined in [draft-ietf-jose-hpke-encrypt, Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5)
	static DecryptionAlg hpke1(PrivateKey privateKey) {
		if (!(privateKey instanceof ECPrivateKey k)) {
			throw new IllegalArgumentException("Private key must be an instance of ECPrivateKey");
		}
		return new HPKEIntegratedAlg(HPKE.hpke1(), null, Curve.P384.ensureSameCurve(k));
	}

	/// Integrated Encryption with `HPKE-2`, as defined in [draft-ietf-jose-hpke-encrypt, Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5)
	static IntegratedEncryptionAlg hpke2(PublicKey publicKey) {
		if (!(publicKey instanceof ECPublicKey k)) {
			throw new IllegalArgumentException("Public key must be an instance of ECPublicKey");
		}
		return new HPKEIntegratedAlg(HPKE.hpke2(), Curve.P521.ensureSameCurve(k), null);
	}

	/// Integrated Encryption with `HPKE-2`, as defined in [draft-ietf-jose-hpke-encrypt, Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5)
	static DecryptionAlg hpke2(PrivateKey privateKey) {
		if (!(privateKey instanceof ECPrivateKey k)) {
			throw new IllegalArgumentException("Private key must be an instance of ECPrivateKey");
		}
		return new HPKEIntegratedAlg(HPKE.hpke2(), null, Curve.P521.ensureSameCurve(k));
	}

	/// Integrated Encryption with `HPKE-9`, as defined in [draft-ietf-jose-hpke-pq-pqt](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-pq-pqt/)
	static IntegratedEncryptionAlg hpke9(PublicKey publicKey) {
		return new HPKEIntegratedAlg(HPKE.hpke9(), asXwingPublicKey(publicKey), null);
	}

	/// Integrated Encryption with `HPKE-9`, as defined in [draft-ietf-jose-hpke-pq-pqt](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-pq-pqt/)
	static DecryptionAlg hpke9(PrivateKey privateKey) {
		return new HPKEIntegratedAlg(HPKE.hpke9(), null, asXwingPrivateKey(privateKey));
	}

	/// Key Encryption with `HPKE-0-KE`, as defined in [draft-ietf-jose-hpke-encrypt, Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6)
	static KeyEncryptionAlg hpke0Ke(PublicKey publicKey) {
		if (!(publicKey instanceof ECPublicKey k)) {
			throw new IllegalArgumentException("Public key must be an instance of ECPublicKey");
		}
		return new HPKEKeyEncryptionAlg(HPKE.hpke0(), Curve.P256.ensureSameCurve(k), null);
	}

	/// Key Encryption with `HPKE-0-KE`, as defined in [draft-ietf-jose-hpke-encrypt, Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6)
	static DecryptionAlg hpke0Ke(PrivateKey privateKey) {
		if (!(privateKey instanceof ECPrivateKey k)) {
			throw new IllegalArgumentException("Private key must be an instance of ECPrivateKey");
		}
		return new HPKEKeyEncryptionAlg(HPKE.hpke0(), null, Curve.P256.ensureSameCurve(k));
	}

	/// Key Encryption with `HPKE-1-KE`, as defined in [draft-ietf-jose-hpke-encrypt, Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6)
	static KeyEncryptionAlg hpke1Ke(PublicKey publicKey) {
		if (!(publicKey instanceof ECPublicKey k)) {
			throw new IllegalArgumentException("Public key must be an instance of ECPublicKey");
		}
		return new HPKEKeyEncryptionAlg(HPKE.hpke1(), Curve.P384.ensureSameCurve(k), null);
	}

	/// Key Encryption with `HPKE-1-KE`, as defined in [draft-ietf-jose-hpke-encrypt, Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6)
	static DecryptionAlg hpke1Ke(PrivateKey privateKey) {
		if (!(privateKey instanceof ECPrivateKey k)) {
			throw new IllegalArgumentException("Private key must be an instance of ECPrivateKey");
		}
		return new HPKEKeyEncryptionAlg(HPKE.hpke1(), null, Curve.P384.ensureSameCurve(k));
	}

	/// Key Encryption with `HPKE-2-KE`, as defined in [draft-ietf-jose-hpke-encrypt, Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6)
	static KeyEncryptionAlg hpke2Ke(PublicKey publicKey) {
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
	static KeyEncryptionAlg hpke9Ke(PublicKey publicKey) {
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
