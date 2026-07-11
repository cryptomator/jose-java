package org.cryptomator.jose;

import org.cryptomator.jose.alg.HPKEIntegratedAlg;

/// HPKE Integrated Encryption as defined in [draft-ietf-jose-hpke-encrypt, Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5):
/// HPKE encrypts the payload directly — there is no CEK, no `enc` or `ek` header parameter, the JWE IV and Authentication Tag are empty, and there is exactly one recipient.
public sealed interface IntegratedEncryptionAlg extends EncryptionAlg permits HPKEIntegratedAlg {

	/// Encrypts the payload in a single HPKE operation.
	///
	/// @param plaintext The JWE payload
	/// @param aad The JWE Additional Authenticated Data encryption parameter, i.e. `ASCII(BASE64URL(protected) [ '.' BASE64URL(aad) ])`
	Sealed seal(byte[] plaintext, byte[] aad);

	/// The result of a single HPKE seal operation.
	///
	/// @param encapsulation The HPKE encapsulated secret (becomes the JWE Encrypted Key)
	/// @param ciphertext The HPKE ciphertext (becomes the JWE Ciphertext, authentication tag included)
	record Sealed(byte[] encapsulation, byte[] ciphertext) {
	}

}
