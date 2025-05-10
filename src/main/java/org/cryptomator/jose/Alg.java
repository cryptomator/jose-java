package org.cryptomator.jose;

import org.cryptomator.jose.alg.EcdhEsAlg;
import org.cryptomator.jose.alg.Pbes2Alg;

import java.security.PrivateKey;
import java.security.PublicKey;

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
		return new EcdhEsAlg(null, privateKey);
	}

	static EncryptionAlg ecdhEs(PublicKey publicKey) {
		return new EcdhEsAlg(publicKey, null);
	}

}
