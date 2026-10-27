package org.cryptomator.jose;

import com.google.gson.JsonObject;
import org.cryptomator.jose.alg.AbstractKeyAlg;

import java.util.Set;

/// Key Encryption: the alg encrypts the content encryption key (CEK); the payload is encrypted by a separate [Enc].
public sealed interface KeyEncryptionAlg extends EncryptionAlg permits AbstractKeyAlg, SymmetricKeyAlg, HpkeKeyEncryptionAlg {

	/// @param combinedHeader The combined header (i.e. protected and shared unprotected), already containing the `enc` header parameter
	/// @param cek The content encryption key to encrypt
	/// @return The encrypted CEK and the header parameters this algorithm generated for the recipient
	/// @apiNote Internal: called by the JWE builder. Users obtain instances via [Alg] and pass them to `JWE.build(...).encrypt(enc, alg...)`.
	EncryptionResult encrypt(JsonObject combinedHeader, byte[] cek);

	/// The names of the header parameters this algorithm generates itself when encrypting (at least `alg`), which a caller must therefore not supply.
	///
	/// @return The generated header parameter names
	/// @apiNote Internal: used by [Recipient] to reject caller-supplied claims that the algorithm generates.
	default Set<String> generatedHeaderParams() {
		return Set.of("alg");
	}

	record EncryptionResult(byte[] encryptedKey, JsonObject recipientSpecificHeader) {
	}

}
