package org.cryptomator.jose;

import org.cryptomator.jose.alg.AbstractKeyAlg;

/// Decryption for the Key Encryption Key Management Mode: the alg decrypts the recipient's JWE Encrypted Key to recover the content encryption key (CEK),
/// which then decrypts the payload. The shared [DecryptionAlg#decrypt] contract composes both steps.
public sealed interface KeyDecryptionAlg extends DecryptionAlg permits AbstractKeyAlg {

}
