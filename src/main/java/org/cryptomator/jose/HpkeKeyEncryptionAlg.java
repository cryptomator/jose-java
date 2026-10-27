package org.cryptomator.jose;

import org.cryptomator.jose.alg.HPKEKeyEncryptionAlg;

/// An HPKE Key Encryption algorithm (`HPKE-*-KE`) holding the recipient's public key, see [draft-ietf-jose-hpke-encrypt, Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6).
/// Runs in HPKE `mode_base` unless a pre-shared key is attached with [#withPsk].
public sealed interface HpkeKeyEncryptionAlg extends KeyEncryptionAlg permits HPKEKeyEncryptionAlg {

	/// Switches to HPKE `mode_psk`: the PSK is mixed into the key schedule and its identifier is emitted as the `psk_id` header parameter, so only a recipient
	/// holding the same PSK can decrypt, and that recipient knows the sender held it too.
	///
	/// @param psk The pre-shared key
	/// @return A copy of this algorithm using the PSK
	HpkeKeyEncryptionAlg withPsk(Psk psk);

}
