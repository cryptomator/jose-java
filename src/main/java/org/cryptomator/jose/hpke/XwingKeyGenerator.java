package org.cryptomator.jose.hpke;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.cryptomator.jose.util.ArrayUtil;
import org.cryptomator.jose.util.X25519;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

/// Helper class to make certain primitives available for X-Wing key generation.
/// See [draft-connolly-cfrg-xwing-kem Section 5.2](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-07#section-5.2)
class XwingKeyGenerator {

	public static KeyPair generateKeyPair(SecureRandom csprng) {
		byte[] sk = new byte[32];
		try {
			csprng.nextBytes(sk);
			return generateKeyPairDerand(sk);
		} finally {
			Arrays.fill(sk, (byte) 0);
		}
	}

	// visible for testing
	public static KeyPair generateKeyPairDerand(byte[] sk) {
		var keys = expandDecapsulationKey(sk);
		var pk = ArrayUtil.concat(extractRawBytes(keys.m().getPublic()), extractRawBytes(keys.x().getPublic()));
		return new KeyPair(new XwingPublicKey(pk), new XwingPrivateKey(sk));
	}

	private static byte[] extractRawBytes(PublicKey publicKey) {
		// TODO: replace with https://openjdk.org/jeps/470
		if (!"X.509".equals(publicKey.getFormat())) {
			throw new IllegalArgumentException("Expected X.509 encoded public key, but got: " + publicKey.getFormat());
		}
		byte[] x509 = publicKey.getEncoded();

		if ("ML-KEM".equals(publicKey.getAlgorithm()) && x509.length == XwingPublicKey.SPKI_HEADER_ML_KEM_768.length + 1184) {
			return Arrays.copyOfRange(x509, XwingPublicKey.SPKI_HEADER_ML_KEM_768.length, x509.length); // the last 1184 bytes are the raw key
		} else if ("XDH".equals(publicKey.getAlgorithm()) && x509.length == XwingPublicKey.SPKI_HEADER_X25519.length + 32) {
			return Arrays.copyOfRange(x509, XwingPublicKey.SPKI_HEADER_X25519.length, x509.length); // the last 32 bytes are the raw key
		} else {
			throw new IllegalArgumentException("Unexpected public key format or length: " + publicKey.getAlgorithm() + ", length: " + x509.length);
		}

		// alternatively use bouncy castle:
//		try {
//			byte[] x509Encoded = publicKey.getEncoded();
//			SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(x509Encoded));
//			return spki.getPublicKeyData().getBytes();  // This is the raw 1184 bytes
//		} catch (IOException e) {
//			throw new IllegalArgumentException("Failed to parse X.509 encoded public key", e);
//		}
	}

	/// @param m The ML-KEM key pair `sk_M` and `pk_M`
	/// @param x The X25519 key pair `sk_X` and `pk_X`
	record XwingKeyPair(KeyPair m, KeyPair x) {}

	/// derives key material from the given secret key
	/// @param sk the secret key that seeds key derivation
	public static XwingKeyPair expandDecapsulationKey(byte[] sk) {
		var expanded = shake256(sk, 96);
		byte[] d = Arrays.copyOfRange(expanded, 0, 32); // d is the first 32 bytes
		byte[] z = Arrays.copyOfRange(expanded, 32, 64); // z is the next 32 bytes
		byte[] skX = Arrays.copyOfRange(expanded, 64, 96); // skX is the last 32 bytes
		Arrays.fill(expanded, (byte) 0);

		KeyPair m;
		try {
			m = keyGenInternal(d, z);
		} finally {
			Arrays.fill(d, (byte) 0);
			Arrays.fill(z, (byte) 0);
		}

		KeyPair x;
		try {
			x = deriveX25519KeyPair(skX);
		} finally {
			Arrays.fill(skX, (byte) 0);
		}

		return new XwingKeyPair(m, x);
	}

	/// derives the public key and returns a KeyPair containing the public and private key.
	/// @param sk the secret key scalar
	private static KeyPair deriveX25519KeyPair(byte[] sk) {
		assert sk.length == 32 : "Secret key must be 32 bytes long";
		var privateKey = X25519.privateKey(sk);
		var basePoint = X25519.basePoint();

		// applying x25519 on secret key and base point yields the public key:
		byte[] pk = X25519.dh(privateKey, basePoint);

		// turn public key bytes into an object:
		var u = new BigInteger(1, ArrayUtil.reverse(pk)); // pk is little endian
		var publicKey = X25519.publicKey(u);
		return new KeyPair(publicKey, privateKey);
	}

	private static byte[] shake256(byte[] input, int byteLength) {
		SHAKEDigest digest = new SHAKEDigest(256);
		digest.update(input, 0, input.length);
		byte[] output = new byte[byteLength];
		digest.doFinal(output, 0, byteLength);
		return output;
	}

	/// `KeyGen_internal` is private API, however we can use a mocked RND to generate a key pair from a given d and z.
	public static KeyPair keyGenInternal(byte[] d, byte[] z) {
		if (d.length != 32 || z.length != 32) {
			throw new IllegalArgumentException("d and z must be 32 bytes long");
		}

		ByteBuffer buf = ByteBuffer.allocate(64);
		buf.put(d);
		buf.put(z);
		buf.flip();

		// This SecureRandom implementation is a workaround to provide a fixed seed for the key generation.
		// See internals of com.sun.crypto.provider.ML_KEM_Impls$KPG#implGenerateKeyPair
		SecureRandom rnd = new SecureRandom() {
			@Override
			public void nextBytes(byte[] bytes) {
				if (bytes.length != 32 || buf.remaining() < 32) {
					throw new IllegalStateException("Expected to provide 2x 32 bytes.");
				}
				buf.get(bytes);
			}

			@Override
			public byte[] generateSeed(int numBytes) {
				throw new UnsupportedOperationException();
			}
		};

		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance("ML-KEM");
			g.initialize(NamedParameterSpec.ML_KEM_768, rnd);
			return g.generateKeyPair();
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new UnsupportedOperationException("Failed to generate ML-KEM key pair", e);
		}
	}

	private XwingKeyGenerator() {
		// Utility class, no instantiation allowed
	}

}
