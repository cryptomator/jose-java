package org.cryptomator.jose.alg;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.SymmetricKeyAlg;
import org.cryptomator.jose.util.CryptoHelper;
import org.cryptomator.jose.util.Destroyables;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.Set;

/// Key Encryption with [PBES2](https://www.rfc-editor.org/rfc/rfc7518#section-4.8). One instance serves both directions.
public final class Pbes2Alg extends AbstractKeyAlg implements SymmetricKeyAlg {

	public enum Type {
		// see RFC 7518 Section 4.8: the PRF is HMAC with the named hash, the derived key length is the AES-KW key size
		PBES2_HS256_A128KW("PBES2-HS256+A128KW", "PBKDF2WithHmacSHA256", 16),
		PBES2_HS512_A256KW("PBES2-HS512+A256KW", "PBKDF2WithHmacSHA512", 32),
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

	/// The default PBKDF2 iteration count used for encryption: OWASP's recommendation for PBKDF2-HMAC-SHA512, well above [#MIN_P2C].
	public static final int DEFAULT_P2C = 210_000;

	/// The minimum PBKDF2 iteration count accepted for encryption, as recommended by [RFC 7518, Section 4.8.1.2](https://www.rfc-editor.org/rfc/rfc7518#section-4.8.1.2).
	public static final int MIN_P2C = 1000;

	/// The maximum PBKDF2 iteration count accepted on both sides (the same cap nimbus-jose-jwt applies on decryption), so that every token produced can also be decrypted.
	public static final int MAX_P2C = 1_000_000;

	private static final int SALT_LEN = 16;
	private static final int MIN_SALT_LEN = 8; // RFC 7518 Section 4.8.1.1

	private final Type algType;
	private final char[] password;
	private final int p2c;

	/// @param algType PBES2 algorithm type
	/// @param password the password used to derive the wrapping key, which remains owned (and eventually wiped) by the caller
	/// @param p2c the PBKDF2 iteration count used for encryption, between [#MIN_P2C] and [#MAX_P2C] (ignored for decryption, where it is read from the header)
	/// @throws IllegalArgumentException if p2c is below the minimum of 1000 recommended by [RFC 7518, Section 4.8.1.2](https://www.rfc-editor.org/rfc/rfc7518#section-4.8.1.2) or above [#MAX_P2C]
	/// @throws NullPointerException if password is null
	public Pbes2Alg(Type algType, char[] password, int p2c) {
		if (p2c < MIN_P2C || p2c > MAX_P2C) {
			throw new IllegalArgumentException("p2c must be between " + MIN_P2C + " and " + MAX_P2C + ", but was: " + p2c);
		}
		this.algType = algType;
		this.password = Objects.requireNonNull(password, "password"); // PBEKeySpec would silently treat null as the empty password
		this.p2c = p2c;
	}

	@Override
	public String name() {
		return algType.jwaAlgName;
	}

	@Override
	public Set<String> generatedHeaderParams() {
		return Set.of("alg", "p2s", "p2c");
	}

	@Override
	protected byte[] decryptKey(JsonObject combinedHeader, byte[] encryptedKey) throws JoseDecryptException {
		var algHeader = combinedHeader.get("alg");
		if (algHeader == null || !algHeader.isJsonPrimitive() || !name().equals(algHeader.getAsString())) {
			throw new DecryptKeyException("alg is not " + algType.jwaAlgName);
		}
		var p2s = decodeP2s(combinedHeader.get("p2s"));
		var p2c = decodeP2c(combinedHeader.get("p2c"));
		var wrappingKeyBytes = pbkdf2(algType, password, p2s, p2c);
		try {
			return AesKw.unwrap(CryptoHelper.secretKey(wrappingKeyBytes, "AES"), encryptedKey);
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
			var encryptedKey = AesKw.wrap(CryptoHelper.secretKey(wrappingKeyBytes, "AES"), cek);
			return new EncryptionResult(encryptedKey, perRecipientHeader);
		} finally {
			Arrays.fill(wrappingKeyBytes, (byte) 0x00);
		}
	}

	// the PBES2 Salt Input, see RFC 7518 Section 4.8.1.1: a base64url string encoding at least 8 octets
	private static byte[] decodeP2s(JsonElement p2sHeader) throws DecryptKeyException {
		if (p2sHeader == null || !p2sHeader.isJsonPrimitive() || !p2sHeader.getAsJsonPrimitive().isString()) {
			throw new DecryptKeyException("Missing or non-string p2s header");
		}
		final byte[] p2s;
		try {
			p2s = Base64.getUrlDecoder().decode(p2sHeader.getAsString());
		} catch (IllegalArgumentException e) {
			throw new DecryptKeyException("p2s header is not base64url", e);
		}
		if (p2s.length < MIN_SALT_LEN) {
			throw new DecryptKeyException("p2s must be at least " + MIN_SALT_LEN + " bytes long");
		}
		return p2s;
	}

	// the PBES2 Count, see RFC 7518 Section 4.8.1.2: a positive integer, capped to keep hostile tokens from consuming unbounded CPU time
	private static int decodeP2c(JsonElement p2cHeader) throws DecryptKeyException {
		if (p2cHeader == null || !p2cHeader.isJsonPrimitive() || !p2cHeader.getAsJsonPrimitive().isNumber()) {
			throw new DecryptKeyException("Missing or non-numeric p2c header");
		}
		var p2c = p2cHeader.getAsNumber().doubleValue();
		if (p2c != Math.rint(p2c) || p2c < 1 || p2c > MAX_P2C) {
			throw new DecryptKeyException("p2c must be an integer between 1 and " + MAX_P2C);
		}
		return (int) p2c;
	}

	private static byte[] pbkdf2(Type type, char[] password, byte[] p2s, int p2c) {
		// the PBKDF2 salt is UTF8(alg) || 0x00 || p2s, see RFC 7518 Section 4.8.1.1
		var algBytes = type.jwaAlgName.getBytes(StandardCharsets.UTF_8);
		var salt = ByteBuffer.allocate(algBytes.length + 1 + p2s.length).put(algBytes).put((byte) 0x00).put(p2s).array();
		// PBEKeySpec and the derived PBKDF2 key each hold their own copy of the password, which only clearPassword()/destroy() wipe
		var spec = new PBEKeySpec(password, salt, p2c, type.keyLength * Byte.SIZE);
		try {
			var keyFactory = SecretKeyFactory.getInstance(type.jcaAlgName);
			var key = keyFactory.generateSecret(spec);
			try {
				return key.getEncoded();
			} finally {
				Destroyables.destroyQuietly(key);
			}
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(type.jcaAlgName + " not supported on this JVM", e);
		} catch (InvalidKeySpecException e) {
			throw new IllegalArgumentException(e);
		} finally {
			spec.clearPassword();
		}
	}
}
