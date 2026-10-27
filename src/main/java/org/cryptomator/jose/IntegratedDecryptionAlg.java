package org.cryptomator.jose;

import org.cryptomator.jose.alg.HPKEIntegratedAlg;

/// Decryption for the Integrated Encryption Key Management Mode: HPKE decrypts the payload directly, without a separate content encryption key.
/// Decrypts HPKE `mode_base` tokens unless a pre-shared key is attached with [#withPsk], after which it decrypts `mode_psk` tokens only.
public sealed interface IntegratedDecryptionAlg extends DecryptionAlg permits HPKEIntegratedAlg {

	/// Switches to HPKE `mode_psk`: the token's `psk_id` protected header parameter must name this PSK, and decryption only succeeds if the sender used the
	/// same PSK. A `mode_base` token (no `psk_id`) is then refused, since it carries no sender authentication.
	///
	/// @param psk The pre-shared key
	/// @return A copy of this algorithm using the PSK
	IntegratedDecryptionAlg withPsk(Psk psk);

}
