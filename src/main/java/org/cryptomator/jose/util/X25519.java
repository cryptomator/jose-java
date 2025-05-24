package org.cryptomator.jose.util;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;

public class X25519 {

	public static KeyFactory keyFactory() {
		record Holder () {
			static final KeyFactory INSTANCE = createKeyFactory();
		}
		return Holder.INSTANCE;
	}

	/// returns the X25519 base point public key
	/// @return a {@link XECPublicKey} with the base point 9 (see RFC 7748)
	public static XECPublicKey basePoint() {
		record Holder () {
			static final XECPublicKey INSTANCE = publicKey(BigInteger.valueOf(9L));
		}
		return Holder.INSTANCE;
	}

	public static byte[] dh(PrivateKey privateKey, PublicKey publicKey) {
		try {
			var keyAgreement = KeyAgreement.getInstance("X25519");
			keyAgreement.init(privateKey);
			keyAgreement.doPhase(publicKey, true);
			return keyAgreement.generateSecret();
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("JVM does not support X25519", e);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Unsuitable key", e);
		}
	}

	public static XECPrivateKey privateKey(byte[] sk) {
		try {
			return (XECPrivateKey) keyFactory().generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, sk));
		} catch (InvalidKeySpecException e) {
			throw new IllegalStateException("Internal error", e);
		}
	}

	public static XECPublicKey publicKey(BigInteger u) {
		try {
			return (XECPublicKey) keyFactory().generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, u));
		} catch (InvalidKeySpecException e) {
			throw new IllegalStateException("Internal error", e);
		}
	}

	private X25519() {
		// prevent instantiation
	}

	private static KeyFactory createKeyFactory() {
		try {
			return KeyFactory.getInstance("X25519");
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("JVM does not support X25519", e);
		}
	}

}
