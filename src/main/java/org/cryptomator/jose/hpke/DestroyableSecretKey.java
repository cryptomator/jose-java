package org.cryptomator.jose.hpke;

import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;
import java.util.Arrays;

/// A [SecretKey] whose key bytes can actually be wiped. Unlike [javax.crypto.spec.SecretKeySpec], whose `destroy()` is the [Destroyable] default
/// and merely throws, this owns a single buffer that [#destroy()] zeroes, after which the key is unusable.
///
/// This is best effort: it covers the copies this library holds (KEM shared secrets, HPKE AEAD keys). Copies made inside the JDK, e.g. a cipher's
/// expanded key schedule or a provider-created `SecretKeySpec`, are outside its control.
public final class DestroyableSecretKey implements SecretKey, Destroyable {

	private final byte[] key;
	private final String algorithm;
	private boolean destroyed;

	/// @param key The key bytes, copied; the caller remains responsible for wiping its own array
	/// @param algorithm The JCA algorithm name reported by [#getAlgorithm()]
	public DestroyableSecretKey(byte[] key, String algorithm) {
		this(key, 0, key.length, algorithm);
	}

	/// @param key A buffer holding the key bytes, which are copied; the caller remains responsible for wiping its own buffer
	/// @param offset The offset of the key bytes within the buffer
	/// @param len The number of key bytes
	/// @param algorithm The JCA algorithm name reported by [#getAlgorithm()]
	/// @throws IllegalArgumentException if `offset` and `len` do not describe a range within the buffer
	public DestroyableSecretKey(byte[] key, int offset, int len, String algorithm) {
		if (offset < 0 || len < 0 || offset > key.length - len) {
			throw new IllegalArgumentException("Invalid key range: offset " + offset + ", length " + len + " in " + key.length + " bytes");
		}
		this.key = Arrays.copyOfRange(key, offset, offset + len);
		this.algorithm = algorithm;
	}

	/// Copies an existing key into a destroyable one, e.g. a provider-created `SecretKeySpec` that cannot be wiped itself.
	///
	/// @param key An extractable key
	/// @return A destroyable copy
	/// @throws IllegalArgumentException if the key is not extractable
	public static DestroyableSecretKey copyOf(SecretKey key) {
		var encoded = key.getEncoded();
		if (encoded == null) {
			throw new IllegalArgumentException("Key is not extractable");
		}
		try {
			return new DestroyableSecretKey(encoded, key.getAlgorithm());
		} finally {
			Arrays.fill(encoded, (byte) 0x00);
		}
	}

	@Override
	public String getAlgorithm() {
		return algorithm;
	}

	@Override
	public String getFormat() {
		return "RAW";
	}

	/// @return A copy of the key bytes; the caller is responsible for wiping it
	/// @throws IllegalStateException if the key has been destroyed
	@Override
	public byte[] getEncoded() {
		if (destroyed) {
			throw new IllegalStateException("Key has been destroyed");
		}
		return key.clone();
	}

	@Override
	public void destroy() {
		Arrays.fill(key, (byte) 0x00);
		destroyed = true;
	}

	@Override
	public boolean isDestroyed() {
		return destroyed;
	}

	@Override
	public String toString() {
		return "DestroyableSecretKey[" + algorithm + ", " + (destroyed ? "destroyed" : key.length + " bytes") + "]";
	}

}
