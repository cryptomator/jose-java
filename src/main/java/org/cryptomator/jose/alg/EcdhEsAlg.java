package org.cryptomator.jose.alg;

import com.google.gson.JsonObject;
import org.cryptomator.jose.JoseDecryptException;

import java.security.PrivateKey;
import java.security.PublicKey;

public final class EcdhEsAlg extends AbstractAlg {

	private final PublicKey publicKey;
	private final PrivateKey privateKey;

	public EcdhEsAlg(PublicKey publicKey, PrivateKey privateKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	@Override
	public String name() {
		return "ECDH-ES+A256KW";
	}

	@Override
	public byte[] decrypt(JsonObject combinedHeader, byte[] encryptedKey) throws JoseDecryptException {
		if (privateKey == null) {
			throw new IllegalStateException("No private key available for decryption.");
		}
		return new byte[0];
	}

	@Override
	public EncryptionResult encrypt(byte[] cek) {
		if (publicKey == null) {
			throw new IllegalStateException("No public key available for encryption.");
		}
		return new EncryptionResult(new byte[0], new JsonObject());
	}
}
