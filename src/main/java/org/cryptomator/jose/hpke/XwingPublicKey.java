package org.cryptomator.jose.hpke;

import org.cryptomator.jose.util.ArrayUtil;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;

class XwingPublicKey implements PublicKey {

	// this is a fixed ASN.1 header for an ML-KEM-768 key
	public static final byte[] SPKI_HEADER_ML_KEM_768 = new byte[] {
			(byte) 0x30, (byte) 0x82, (byte) 0x04, (byte) 0xb2, // SEQUENCE of length 1202
			(byte) 0x30, (byte) 0x0b, // SEQUENCE of length 11
			(byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x04, (byte) 0x02, // OID 2.16.840.1.101.3.4.4.2
			(byte) 0x03, (byte) 0x82, (byte) 0x04, (byte) 0xa1, // BIT STRING of length 1185
			(byte) 0x00
	};

	// this is a fixed ASN.1 header for an X25519 key
	public static final byte[] SPKI_HEADER_X25519 = new byte[] {
			(byte) 0x30, (byte) 0x2a, // SEQUENCE of length 42
			(byte) 0x30, (byte) 0x05, // SEQUENCE of length 5
			(byte) 0x06, (byte) 0x03, (byte) 0x2b, (byte) 0x65, (byte) 0x6e, // OID 1.3.101.110
			(byte) 0x03, (byte) 0x21, // BIT STRING of length 33
			(byte) 0x00
	};

	private final byte[] pk;

	public XwingPublicKey(byte[] pk) {
		if (pk == null || pk.length < 1216) {
			throw new IllegalArgumentException("Public key cannot be null or empty");
		}
		this.pk = Arrays.copyOf(pk, pk.length);
	}

	@Override
	public String getAlgorithm() {
		return "X-Wing";
	}

	@Override
	public String getFormat() {
		return "RAW";
	}

	@Override
	public byte[] getEncoded() {
		return pk.clone();
	}

	/// returns the ML-KEM public key part (`pk_M = pk[0:1184]`)
	/// @return a new {@link PublicKey} instance
	public PublicKey getMLKemPublicKey() {
		var subkey = Arrays.copyOfRange(pk, 0, 1184);
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("ML-KEM");
			return keyFactory.generatePublic(new X509EncodedKeySpec(ArrayUtil.concat(SPKI_HEADER_ML_KEM_768, subkey)));
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("JVM does not support ML-KEM", e);
		} catch (InvalidKeySpecException e) {
			throw new IllegalStateException("Internal error", e);
		}
	}

	/// returns the X25519 public key part (`pk_X = pk[1184:1216]`)
	/// @return a new {@link XECPublicKey} instance
	public XECPublicKey getX25519PublicKey() {
		var subkey = Arrays.copyOfRange(pk, 1184, 1216);
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("X25519");
			var u = new BigInteger(1, ArrayUtil.reverse(subkey)); // really reverse?
			return (XECPublicKey) keyFactory.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, u));
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("JVM does not support X25519", e);
		} catch (InvalidKeySpecException e) {
			throw new IllegalStateException("Internal error", e);
		}
	}

}
