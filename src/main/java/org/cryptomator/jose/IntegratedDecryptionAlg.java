package org.cryptomator.jose;

import org.cryptomator.jose.alg.HPKEIntegratedAlg;

/// Decryption for the Integrated Encryption Key Management Mode: HPKE decrypts the payload directly, without a separate content encryption key.
public sealed interface IntegratedDecryptionAlg extends DecryptionAlg permits HPKEIntegratedAlg {

}
