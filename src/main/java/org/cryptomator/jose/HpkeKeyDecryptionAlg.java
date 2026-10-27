package org.cryptomator.jose;

import org.cryptomator.jose.alg.HPKEKeyEncryptionAlg;

/// An HPKE Key Encryption algorithm (`HPKE-*-KE`) holding the recipient's private key, see [draft-ietf-jose-hpke-encrypt, Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6).
/// Decrypts HPKE `mode_base` tokens unless a pre-shared key is attached with [#withPsk], after which it decrypts `mode_psk` tokens only.
public sealed interface HpkeKeyDecryptionAlg extends KeyDecryptionAlg permits HPKEKeyEncryptionAlg {

	/// Switches to HPKE `mode_psk`: only recipients whose `psk_id` header parameter names this PSK are decrypted, and only if the sender used the same PSK.
	/// A `mode_base` recipient (no `psk_id`) is then refused, since it carries no sender authentication.
	///
	/// @param psk The pre-shared key
	/// @return A copy of this algorithm using the PSK
	HpkeKeyDecryptionAlg withPsk(Psk psk);

}
