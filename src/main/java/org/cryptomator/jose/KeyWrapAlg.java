package org.cryptomator.jose;

import org.cryptomator.jose.alg.AesKwAlg;

/// A symmetric Key Encryption algorithm: the same key encryption key serves both directions, so one instance is usable as [KeyEncryptionAlg] and as [DecryptionAlg].
public sealed interface KeyWrapAlg extends KeyEncryptionAlg, KeyDecryptionAlg permits AesKwAlg {

}
