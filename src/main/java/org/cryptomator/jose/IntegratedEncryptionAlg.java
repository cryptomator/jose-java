package org.cryptomator.jose;

import com.google.gson.JsonObject;
import org.cryptomator.jose.alg.HPKEIntegratedAlg;

/// HPKE Integrated Encryption as defined in [draft-ietf-jose-hpke-encrypt, Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5):
/// HPKE encrypts the payload directly — there is no CEK, no `enc` or `ek` header parameter, the JWE IV and Authentication Tag are empty, and there is exactly one recipient.
/// Runs in HPKE `mode_base` unless a pre-shared key is attached with [#withPsk].
public sealed interface IntegratedEncryptionAlg extends EncryptionAlg permits HPKEIntegratedAlg {

	/// Encrypts the payload in a single HPKE operation.
	///
	/// @param plaintext The JWE payload
	/// @param aad The JWE Additional Authenticated Data encryption parameter, i.e. `ASCII(BASE64URL(protected) [ '.' BASE64URL(aad) ])`
	/// @return The encapsulated secret and the ciphertext
	/// @apiNote Internal: called by the JWE builder. Users obtain instances via [Alg] and pass them to `JWE.build(...).encrypt(alg)`.
	Sealed seal(byte[] plaintext, byte[] aad);

	/// The header parameters this algorithm generates, which go into the protected header and must not be supplied by the caller: `alg`, plus `psk_id` in `mode_psk`.
	///
	/// @return The generated protected header parameters
	/// @apiNote Internal: called by the JWE builder.
	JsonObject generatedProtectedHeader();

	/// Switches to HPKE `mode_psk`: the PSK is mixed into the key schedule and its identifier is emitted as the `psk_id` protected header parameter, so only a
	/// recipient holding the same PSK can decrypt, and that recipient knows the sender held it too.
	///
	/// @param psk The pre-shared key
	/// @return A copy of this algorithm using the PSK
	IntegratedEncryptionAlg withPsk(Psk psk);

	/// The result of a single HPKE seal operation.
	///
	/// @param encapsulation The HPKE encapsulated secret (becomes the JWE Encrypted Key)
	/// @param ciphertext The HPKE ciphertext (becomes the JWE Ciphertext, authentication tag included)
	record Sealed(byte[] encapsulation, byte[] ciphertext) {
	}

}
