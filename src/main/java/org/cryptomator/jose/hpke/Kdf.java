package org.cryptomator.jose.hpke;

import javax.crypto.SecretKey;

/// HPKE key derivation function as defined in [draft-ietf-hpke-hpke, Section 4.2](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-4.2):
/// either a two-stage KDF with `Extract`/`Expand` functions (e.g. [HKDF]) or a one-stage KDF with a single `Derive` function (e.g. [Shake]).
public sealed interface Kdf permits HKDF, Shake {

	/// Derives `key` and `base_nonce` from the KEM shared secret as defined by `KeySchedule` in
	/// [draft-ietf-hpke-hpke, Section 5.1](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.1), i.e. `CombineSecrets_TwoStage`
	/// or `CombineSecrets_OneStage` depending on the KDF type. The `exporter_secret` is currently not derived, as HPKE's secret export interface is unused.
	///
	/// @param mode         A one-byte value indicating the HPKE mode
	/// @param sharedSecret A KEM shared secret generated for this transaction
	/// @param info         Application-supplied information (optional)
	/// @param psk          A pre-shared key held by both the sender and the recipient (empty if unused)
	/// @param pskId        An identifier for the PSK (empty if unused)
	/// @param suiteId      The `suite_id` of the HPKE ciphersuite, used for domain separation within the labeled derivation functions
	/// @param keyAlg       JCA algorithm name of the derived AEAD key (e.g. `AES`)
	/// @param nk           The AEAD key length `Nk` in bytes
	/// @param nn           The AEAD nonce length `Nn` in bytes
	DerivedKeys combineSecrets(byte mode, SecretKey sharedSecret, byte[] info, byte[] psk, byte[] pskId, byte[] suiteId, String keyAlg, int nk, int nn);

	record DerivedKeys(SecretKey key, byte[] baseNonce) {
	}

}
