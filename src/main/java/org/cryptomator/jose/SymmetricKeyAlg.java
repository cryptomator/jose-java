package org.cryptomator.jose;

import org.cryptomator.jose.alg.AesKwAlg;
import org.cryptomator.jose.alg.Pbes2Alg;

/// A symmetric key management algorithm: the same secret (a key encryption key or a password) serves both directions, so one instance is usable as [KeyEncryptionAlg] and as [DecryptionAlg].
public sealed interface SymmetricKeyAlg extends KeyEncryptionAlg, KeyDecryptionAlg permits AesKwAlg, Pbes2Alg {

}
