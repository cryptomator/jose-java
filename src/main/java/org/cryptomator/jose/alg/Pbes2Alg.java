package org.cryptomator.jose.alg;

import com.google.gson.JsonObject;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.util.CryptoHelper;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

/// Key Encryption with [PBES2](https://www.rfc-editor.org/rfc/rfc7518#section-4.8)
public final class Pbes2Alg extends AbstractAlg {

	public enum Type {
		PBES2_HS256_A128KW("PBES2-HS256+A128KW", "PBKDF2WithHmacSHA512", 32),
		PBES2_HS512_A256KW("PBES2-HS512+A256KW", "PBKDF2WithHmacSHA512", 16),
		;

		private final String jwaAlgName;
		private final String jcaAlgName;
		private final int keyLength;

		Type(String jwaAlgName, String jcaAlgName, int keyLength) {
			this.jwaAlgName = jwaAlgName;
			this.jcaAlgName = jcaAlgName;
			this.keyLength = keyLength;
		}
	}

	private static final int SALT_LEN = 16;

	private final Type algType;
	private final char[] password;
	private final int p2c;

	/// @param algType PBES2 algorithm type
	/// @param password the password used to derive the wrapping key
	/// @param p2c the PBKEDF2 iteration count (will be ignored for decryption)
	public Pbes2Alg(Type algType, char[] password, int p2c) {
		this.algType = algType;
		this.password = password;
		this.p2c = p2c;
	}

	@Override
	public String name() {
		return algType.jwaAlgName;
	}

	@Override
	public byte[] decrypt(JsonObject combinedHeader, byte[] encryptedKey) throws JoseDecryptException {
		if (!name().equals(combinedHeader.get("alg").getAsString())) {
			throw new IllegalArgumentException("alg is not " + algType.jwaAlgName);
		}
		if (!combinedHeader.has("p2s")) {
			throw new IllegalArgumentException("p2s is missing");
		}
		if (!combinedHeader.has("p2c")) {
			throw new IllegalArgumentException("p2c is missing");
		}

		var p2s = Base64.getUrlDecoder().decode(combinedHeader.get("p2s").getAsString());
		var p2c = combinedHeader.get("p2c").getAsInt();
		var wrappingKeyBytes = pbkdf2(algType, password, p2s, p2c);

		try {
			var wrappingKey = CryptoHelper.secretKey(wrappingKeyBytes, "AES");
			var cipher = Cipher.getInstance("AESWrap");
			cipher.init(Cipher.UNWRAP_MODE, wrappingKey);
			var unwrappedKey = cipher.unwrap(encryptedKey, "AES", Cipher.SECRET_KEY);
			return unwrappedKey.getEncoded();
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new AssertionError("JVM doesn't support AWS Key wrap", e);
		} catch (InvalidKeyException e) {
			throw new DecryptKeyException("Key unwrapping failed with given kek", e);
		} finally {
			Arrays.fill(wrappingKeyBytes, (byte) 0x00);
		}
	}

	@Override
	public EncryptionResult encrypt(JsonObject combinedHeader, byte[] cek) {
		var p2s = CryptoHelper.randomBytes(SALT_LEN);
		JsonObject perRecipientHeader = new JsonObject();
		perRecipientHeader.addProperty("alg", algType.jwaAlgName);
		perRecipientHeader.addProperty("p2c", p2c);
		perRecipientHeader.addProperty("p2s", Base64.getUrlEncoder().withoutPadding().encodeToString(p2s));
		var wrappingKeyBytes = pbkdf2(algType, password, p2s, p2c);

		try {
			var keyToWrap = CryptoHelper.secretKey(cek, "AES");
			var wrappingKey = CryptoHelper.secretKey(wrappingKeyBytes, "AES");
			var cipher = Cipher.getInstance("AESWrap");
			cipher.init(Cipher.WRAP_MODE, wrappingKey);
			var encryptedKey = cipher.wrap(keyToWrap);
			return new EncryptionResult(encryptedKey, perRecipientHeader);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new AssertionError("JVM doesn't support AWS Key wrap", e);
		} catch (InvalidKeyException e) {
			throw new IllegalStateException("Key derived via PBKDF2 deemed inappropriate for key wrapping", e);
		} catch (IllegalBlockSizeException e) {
			throw new IllegalStateException("Wrapping key should not produce IllegalBlockSizeException", e);
		} finally {
			Arrays.fill(wrappingKeyBytes, (byte) 0x00);
		}
	}

	private static byte[] pbkdf2(Type type, char[] password, byte[] p2s, int p2c) {
		try {
			var spec = new PBEKeySpec(password, p2s, p2c, type.keyLength * Byte.SIZE);
			var keyFactory = SecretKeyFactory.getInstance(type.jcaAlgName);
			return keyFactory.generateSecret(spec).getEncoded();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(type.jcaAlgName + " not supported on this JVM", e);
		} catch (InvalidKeySpecException e) {
			throw new IllegalArgumentException(e);
		}
	}
}
