package org.cryptomator.jose;

import org.cryptomator.jose.alg.HPKEIntegratedAlg;

/// Decryption for the Integrated Encryption Key Management Mode: HPKE decrypts the payload directly, without a separate content encryption key.
/// Only HPKE `mode_base` is supported; a token with a `psk_id` header parameter (`mode_psk`) cannot be decrypted.
public sealed interface IntegratedDecryptionAlg extends DecryptionAlg permits HPKEIntegratedAlg {

}
