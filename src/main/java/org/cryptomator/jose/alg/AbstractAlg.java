package org.cryptomator.jose.alg;

import org.cryptomator.jose.DecryptionAlg;
import org.cryptomator.jose.EncryptionAlg;

public sealed abstract class AbstractAlg implements DecryptionAlg, EncryptionAlg permits EcdhEsAlg, Pbes2Alg, HPKEAlg {


}
