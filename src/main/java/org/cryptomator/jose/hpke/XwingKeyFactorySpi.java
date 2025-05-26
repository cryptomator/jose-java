package org.cryptomator.jose.hpke;

import org.cryptomator.jose.util.ArrayUtil;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class XwingKeyFactorySpi extends KeyFactorySpi {

	public static final byte[] X509_HEADER = new byte[] {
			(byte) 0x30, (byte) 0x82, (byte) 0x04, (byte) 0xd4, // SEQUENCE of length 1236
			(byte) 0x30, (byte) 0x0d, // SEQUENCE of length 13
			(byte) 0x06, (byte) 0x0B, (byte) 0x2B, (byte) 0x06, (byte) 0x01, (byte) 0x04, (byte) 0x01, (byte) 0x83, (byte) 0xE6, (byte) 0x2D, (byte) 0x81, (byte) 0xC8, (byte) 0x7A, // OID 1.3.6.1.4.1.62253.25722
			(byte) 0x03, (byte) 0x82, (byte) 0x04, (byte) 0xc1, (byte) 0x00 // BIT STRING of length 1217
	};

	private static final byte[] PKCS8_HEADER = new byte[] {
			(byte) 0x30, (byte) 0x34, // SEQUENCE of length 54
			(byte) 0x02, (byte) 0x01, (byte) 0x00, // VERSION 0
			(byte) 0x30, (byte) 0x0d, // SEQUENCE of length 13
			(byte) 0x06, (byte) 0x0B, (byte) 0x2B, (byte) 0x06, (byte) 0x01, (byte) 0x04, (byte) 0x01, (byte) 0x83, (byte) 0xE6, (byte) 0x2D, (byte) 0x81, (byte) 0xC8, (byte) 0x7A, // OID 1.3.6.1.4.1.62253.25722
			(byte) 0x04, (byte) 0x20 // OCTET STRING of length 32
	};

	@Override
	protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
		var bytes = switch (keySpec) {
			case X509EncodedKeySpec s -> fromX509(s.getEncoded());
			case EncodedKeySpec s when "RAW".equals(s.getFormat()) -> s.getEncoded();
			default -> throw new InvalidKeySpecException("Unsupported key spec: " + keySpec.getClass().getName());
		};
		return new XwingPublicKey(bytes);
	}

	@Override
	protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
		byte[] bytes = new byte[0];
		try {
			bytes = switch (keySpec) {
				case PKCS8EncodedKeySpec s -> fromPKCS8(s::getEncoded);
				case EncodedKeySpec s when "RAW".equals(s.getFormat()) -> s.getEncoded();
				default -> throw new InvalidKeySpecException("Unsupported key spec: " + keySpec.getClass().getName());
			};
			return new XwingPrivateKey(bytes);
		}  catch (IllegalArgumentException e) {
			throw new InvalidKeySpecException(e);
		} finally {
			Arrays.fill(bytes, (byte) 0x00);
		}
	}

	@Override
	protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
		if (key instanceof XwingPublicKey publicKey && keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
			return keySpec.cast(new X509EncodedKeySpec(toX509(publicKey.getEncoded())));
		} else if (key instanceof XwingPrivateKey privateKey && keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
			return keySpec.cast(new PKCS8EncodedKeySpec(toPKCS8(privateKey.getEncoded())));
		} else {
			throw new InvalidKeySpecException("Unsupported key type: " + key.getClass().getName());
		}
	}

	@Override
	protected Key engineTranslateKey(Key key) throws InvalidKeyException {
		try {
			return switch (key) {
				case XwingPublicKey publicKey -> publicKey;
				case XwingPrivateKey privateKey -> privateKey;
				case PublicKey k when "RAW".equals(k.getFormat()) -> new XwingPublicKey(k.getEncoded());
				case PrivateKey k when "RAW".equals(k.getFormat()) -> new XwingPrivateKey(k.getEncoded());
				case PublicKey k when "X.509".equals(k.getFormat()) -> new XwingPublicKey(fromX509(k.getEncoded()));
				case PrivateKey k when "PKCS#8".equals(k.getFormat()) -> new XwingPrivateKey(fromPKCS8(k::getEncoded));
				default -> throw new InvalidKeyException("Unsupported key type: " + key.getClass().getName());
			};
		} catch (IllegalArgumentException e) {
			throw new InvalidKeyException(e);
		}
	}

	private static byte[] fromX509(byte[] encoded) {
		if (encoded == null || encoded.length != X509_HEADER.length + 1216) {
			throw new IllegalArgumentException("SPKI encoded public key must be " + X509_HEADER.length + 1216 + " bytes long");
		}
		return Arrays.copyOfRange(encoded, X509_HEADER.length, encoded.length); // remove header
	}

	private static byte[] toX509(byte[] encoded) {
		if (encoded == null || encoded.length != 1216) {
			throw new IllegalArgumentException("Public key must be 1216 bytes long");
		}
		return ArrayUtil.concat(X509_HEADER, encoded);
	}

	private static byte[] fromPKCS8(Encodable encodable) {
		var encoded = encodable.getEncoded();
		try {
			return fromPKCS8(encoded);
		} finally {
			Arrays.fill(encoded, (byte) 0x00);
		}
	}

	private static byte[] fromPKCS8(byte[] encoded) {
		// FIXME: PKCS8 allows for optional attributes, so the length check is not correct
		if (encoded == null || encoded.length != PKCS8_HEADER.length + 32) {
			throw new IllegalArgumentException("PKCS#8 encoded private key must be " + PKCS8_HEADER.length + 32 + " bytes long");
		}
		return Arrays.copyOfRange(encoded, PKCS8_HEADER.length, encoded.length); // remove header
	}

	private static byte[] toPKCS8(byte[] encoded) {
		if (encoded == null || encoded.length != 32) {
			throw new IllegalArgumentException("Private key must be 32 bytes long");
		}
		return ArrayUtil.concat(PKCS8_HEADER, encoded);
	}

	@FunctionalInterface
	private interface Encodable {
		byte[] getEncoded();
	}


}
