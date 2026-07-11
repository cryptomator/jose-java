package org.cryptomator.jose;

/// An algorithm capable of encrypting a JWE for one recipient (holding the recipient's public key or password).
/// The JWE Key Management Mode is determined by the subtype: [KeyEncryptionAlg] encrypts a content encryption key,
/// [IntegratedEncryptionAlg] encrypts the payload itself.
public sealed interface EncryptionAlg extends Alg permits KeyEncryptionAlg, IntegratedEncryptionAlg {

}
