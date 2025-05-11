package org.cryptomator.jose.alg;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

class ConcatKDF {

	private final String hashAlg;
	private final long maxInputLength;

	private ConcatKDF(String hashAlg, long maxInputLength) throws NoSuchAlgorithmException {
		this.hashAlg = MessageDigest.getInstance(hashAlg).getAlgorithm(); // trigger NoSuchAlgorithmException early; see createMessageDigest()
		this.maxInputLength = maxInputLength;
	}

	public static ConcatKDF sha256() {
		var hashAlg = "SHA-256";
		var maxInputLength = Long.MAX_VALUE; // technically max input length for sha256 is 2^64-1 bits
		try {
			return new ConcatKDF(hashAlg, maxInputLength);
		} catch (NoSuchAlgorithmException e) {
			throw new AssertionError("Every implementation of the Java platform is required to support [...] SHA-256", e);
		}
	}

	private MessageDigest createMessageDigest() {
		try {
			return MessageDigest.getInstance(hashAlg);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Digest creation was successful in constructor", e);
		}
	}

	/// KDF as defined in [NIST SP 800-56A Rev. 2 Section 5.8.1](https://doi.org/10.6028/NIST.SP.800-56Ar2) using SHA-256
	/// @param z A shared secret
	/// @param keyDataLen Desired key length (in bytes)
	/// @param otherInfo Optional context info binding the derived key to a key agreement (see e.g. RFC 7518, Section 4.6.2)
	/// @return key data
	public byte[] kdf(byte[] z, int keyDataLen, byte[] otherInfo) {
		final MessageDigest hash = createMessageDigest();
		final int hashLen = hash.getDigestLength();

		// step 1
		final int reps = Math.ceilDivExact(keyDataLen, hashLen);

		// step 2
		assert reps < Integer.MAX_VALUE; // spec needs reps to be < 2^32 - 1. However, since keyDataLen is an int and hashLen can't be < 1, reps must be < 2^31

		// step 4
		if (Integer.BYTES + z.length + otherInfo.length > maxInputLength) {
			throw new IllegalArgumentException("unsupported input length");
		}

		// step 5-7
		byte[] key = new byte[reps * hashLen];
		ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES + z.length + otherInfo.length);
		buffer.putInt(0); // Counter
		buffer.put(z); // Shared secret
		buffer.put(otherInfo); // Other info
		for (int i = 0; i < reps; i++) {
			buffer.putInt(0, i + 1); // Counter
			byte[] digest = hash.digest(buffer.array());
			System.arraycopy(digest, 0, key, i * hashLen, hashLen);
		}
		return Arrays.copyOf(key, keyDataLen);
	}

}
