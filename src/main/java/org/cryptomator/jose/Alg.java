package org.cryptomator.jose;

import org.cryptomator.jose.alg.EcdhEsAlg;
import org.cryptomator.jose.alg.HPKE2Alg;
import org.cryptomator.jose.alg.HPKE9Alg;
import org.cryptomator.jose.alg.Pbes2Alg;
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

	static EncryptionAlg hpke2(PublicKey publicKey) {
		if (!(publicKey instanceof ECPublicKey k)) {
			throw new IllegalArgumentException("Public key must be an instance of ECPublicKey");
		}
		return new HPKE2Alg(k, null);
	}

	static DecryptionAlg hpke2(PrivateKey privateKey) {
		if (!(privateKey instanceof ECPrivateKey k)) {
			throw new IllegalArgumentException("Private key must be an instance of ECPrivateKey");
		}
		return new HPKE2Alg(null, k);
	}

	static EncryptionAlg hpke9(PublicKey publicKey) {
		try {
			var kf = KeyFactory.getInstance("X-Wing", XwingProvider.INSTANCE);
			var k = (PublicKey) kf.translateKey(publicKey);
			return new HPKE9Alg(k, null);
		} catch (NoSuchAlgorithmException e) {
			throw new AssertionError("Custom X-Wing provider must support X-Wing key factory", e);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Not an X-Wing public key.", e);
		}
	}

	static DecryptionAlg hpke9(PrivateKey privateKey) {
		try {
			var kf = KeyFactory.getInstance("X-Wing", XwingProvider.INSTANCE);
			var k = (PrivateKey) kf.translateKey(privateKey);
			return new HPKE9Alg(null, k);
		} catch (NoSuchAlgorithmException e) {
			throw new AssertionError("Custom X-Wing provider must support X-Wing key factory", e);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Not an X-Wing private key.", e);
		}
	}

}
