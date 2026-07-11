package org.cryptomator.jose.hpke;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public enum AEAD {
	AES128GCM("AES-128-GCM", 16, 12, 16, AEAD::aesEncrypt, AEAD::aesDecrypt),
	AES256GCM("AES-256-GCM", 32, 12, 16, AEAD::aesEncrypt, AEAD::aesDecrypt),
	;

	/// AEAD name
	public final String name;

	/// key length in bytes
	public final int nk;

	/// nonce length in bytes
	public final int nn;

	/// tag length in bytes
	public final int nt;

	// seal/open functions
	private final Sealer sealer;
	private final Opener opener;

	AEAD(String name, int nk, int nn, int nt, Sealer sealer, Opener opener) {
		this.name = name;
		this.nk = nk;
		this.nn = nn;
		this.nt = nt;
		this.sealer = sealer;
		this.opener = opener;
	}

	public byte[] seal(SecretKey key, byte[] nonce, byte[] aad, byte[] pt) {
		return sealer.seal(key, nonce, aad, pt);
	}

	public byte[] open(SecretKey key, byte[] nonce, byte[] aad, byte[] ct) throws AEADBadTagException {
		return opener.open(key, nonce, aad, ct);
	}

	@FunctionalInterface
	private interface Sealer {
		byte[] seal(SecretKey key, byte[] nonce, byte[] aad, byte[] pt);
	}

	@FunctionalInterface
	private interface Opener {
		byte[] open(SecretKey key, byte[] nonce, byte[] aad, byte[] ct) throws AEADBadTagException;
	}

	private static byte[] aesEncrypt(SecretKey key, byte[] nonce, byte[] aad, byte[] pt) {
		try {
			var cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
			cipher.updateAAD(aad);
			return cipher.doFinal(pt);
		} catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
			throw new AssertionError("Every implementation of the Java platform is required to support [...] AES/GCM/NoPadding", e);
		} catch (BadPaddingException e) {
			throw new AssertionError("BadPaddingException occurred during encryption", e);
		} catch (IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidKeyException e) {
			throw new IllegalArgumentException("Encryption failed for given parameters", e);
		}
	}

	private static byte[] aesDecrypt(SecretKey key, byte[] nonce, byte[] aad, byte[] ct) throws AEADBadTagException {
		try {
			var cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
			cipher.updateAAD(aad);
			return cipher.doFinal(ct);
		} catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
			throw new AssertionError("Every implementation of the Java platform is required to support [...] AES/GCM/NoPadding", e);
		} catch (AEADBadTagException e) {
			throw e;
		} catch (BadPaddingException e) {
			throw new IllegalArgumentException("Unauthentic ciphertext", e); // TODO throw checked exception?
		} catch (IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidKeyException e) {
			throw new IllegalArgumentException("Decryption failed for given parameters", e);
		}
	}

}
