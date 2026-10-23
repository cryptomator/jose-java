package org.cryptomator.jose.enc;

import org.cryptomator.jose.Enc;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.util.ArrayUtil;
import org.cryptomator.jose.util.CryptoHelper;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public final class AESGCM implements Enc {

	private static final String CIPHER_ALG_NAME = "AES/GCM/NoPadding";
	private static final String SECRET_KEY_ALG_NAME = "AES";
	private static final int IV_LEN_BYTES = 12; // RFC 7518 Section 5.3: 96-bit IV
	private static final int TAG_LEN_BYTES = 16; // RFC 7518 Section 5.3: 128-bit tag

	private final String name;
	private final int keyLength;

	public AESGCM(String name, int keyLength) {
		this.name = name;
		this.keyLength = keyLength;
	}

	@Override
	public String encValue() {
		return name;
	}

	@Override
	public byte[] generateCek() {
		return CryptoHelper.randomBytes(keyLength);
	}

	@Override
	public byte[] generateIv() {
		return CryptoHelper.randomBytes(IV_LEN_BYTES);
	}

	@Override
	public EncryptionResult encrypt(byte[] cek, byte[] iv, byte[] aad, byte[] plaintext) {
		// the JDK accepts any AES key size and any IV length, so enforce the sizes fixed by RFC 7518 Section 5.3 for the declared enc ourselves
		if (cek.length != keyLength) {
			throw new IllegalArgumentException(name + " requires a " + keyLength + "-byte CEK, but got " + cek.length + " bytes");
		}
		if (iv.length != IV_LEN_BYTES) {
			throw new IllegalArgumentException(name + " requires a " + IV_LEN_BYTES + "-byte IV, but got " + iv.length + " bytes");
		}
		try {
			Cipher cipher = Cipher.getInstance(CIPHER_ALG_NAME);
			var params = new GCMParameterSpec(TAG_LEN_BYTES * Byte.SIZE, iv);
			cipher.init(Cipher.ENCRYPT_MODE, CryptoHelper.secretKey(cek, SECRET_KEY_ALG_NAME), params);
			cipher.updateAAD(aad);
			var ciphertextAndTag = cipher.doFinal(plaintext);
			var ciphertext = Arrays.copyOf(ciphertextAndTag, ciphertextAndTag.length - TAG_LEN_BYTES);
			var tag = Arrays.copyOfRange(ciphertextAndTag, ciphertextAndTag.length - TAG_LEN_BYTES, ciphertextAndTag.length);
			return new EncryptionResult(ciphertext, tag);
		} catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
			throw new AssertionError("AES/GCM/NoPadding not supported on this JVM", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new IllegalArgumentException("invalid IV", e);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("invalid CEK", e);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new AssertionError(e); // IllegalBlockSize: not a block cipher // BadPadding: can only occur during decryption
		}
	}

	@Override
	public byte[] decrypt(byte[] cek, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag) throws JoseDecryptException {
		// RFC 7516 Section 5.2 step 9 and RFC 7518 Section 5.3: the CEK, IV and tag sizes are fixed by the declared enc; the JDK alone would accept other AES key sizes and IV lengths
		if (cek.length != keyLength) {
			throw new DecryptCiphertextException(name + " requires a " + keyLength + "-byte CEK, but got " + cek.length + " bytes");
		}
		if (iv.length != IV_LEN_BYTES) {
			throw new DecryptCiphertextException(name + " requires a " + IV_LEN_BYTES + "-byte IV, but got " + iv.length + " bytes");
		}
		if (tag.length != TAG_LEN_BYTES) {
			throw new DecryptCiphertextException(name + " requires a " + TAG_LEN_BYTES + "-byte tag, but got " + tag.length + " bytes");
		}
		try {
			Cipher cipher = Cipher.getInstance(CIPHER_ALG_NAME);
			var params = new GCMParameterSpec(TAG_LEN_BYTES * Byte.SIZE, iv);
			cipher.init(Cipher.DECRYPT_MODE, CryptoHelper.secretKey(cek, SECRET_KEY_ALG_NAME), params);
			cipher.updateAAD(aad);
			var ciphertextAndTag = ArrayUtil.concat(ciphertext, tag);
			return cipher.doFinal(ciphertextAndTag);
		} catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
			throw new AssertionError("AES/GCM/NoPadding not supported on this JVM", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new DecryptCiphertextException("Invalid IV", e); // e.g. a missing or wrong-length IV on a Key Encryption token
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("invalid CEK", e);
		} catch (IllegalBlockSizeException e) {
			throw new AssertionError(e); // IllegalBlockSize: not a block cipher
		} catch (BadPaddingException e) {
			throw new DecryptCiphertextException("Decryption failed", e);
		}
	}
}
