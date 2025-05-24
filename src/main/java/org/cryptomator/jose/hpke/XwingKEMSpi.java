package org.cryptomator.jose.hpke;

import org.cryptomator.jose.util.ArrayUtil;
import org.cryptomator.jose.util.Destroyables;
import org.cryptomator.jose.util.X25519;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class XwingKEMSpi implements KEMSpi {

	@Override
	public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException {
		if (!(publicKey instanceof XwingPublicKey pk)) {
			throw new InvalidKeyException("Invalid public key: " + publicKey);
		}
		if (secureRandom == null) {
			secureRandom = new SecureRandom();
		}
		return new XwingEncapsulator(pk, secureRandom);
	}

	@Override
	public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException, InvalidKeyException {
		if (!(privateKey instanceof XwingPrivateKey sk)) {
			throw new InvalidKeyException("Invalid private key: " + privateKey);
		}
		return new XwingDecapsulator(sk);
	}

	// https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-07#section-5.3
	private static byte[] combiner(byte[] ssM, byte[] ssX, byte[] ctX, byte[] pkX) {
		var xwinglabel = new byte[] {0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c};
		var input = ArrayUtil.concat(ssM, ssX, ctX, pkX, xwinglabel);
		try {
			MessageDigest sha3 = MessageDigest.getInstance("SHA3-256");
			return sha3.digest(input);
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("SHA3-256 algorithm not supported", e);
		}
	}

	public record XwingEncapsulator(XwingPublicKey pk, SecureRandom secureRandom) implements KEMSpi.EncapsulatorSpi {

		@Override
		public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
			// ML-KEM:
			var pkMKey = pk.getMLKemPublicKey();
			KEM.Encapsulated encapsulated;
			try {
				KEM kem = KEM.getInstance("ML-KEM");
				KEM.Encapsulator enc = kem.newEncapsulator(pkMKey, secureRandom);
				encapsulated = enc.encapsulate();
			} catch (NoSuchAlgorithmException e) {
				throw new UnsupportedOperationException("ML-KEM algorithm not supported", e);
			} catch (InvalidKeyException e) {
				throw new IllegalArgumentException("Invalid ML-KEM key part of X-Wing public key", e);
			}
			var ssM = encapsulated.key().getEncoded();
			var ctM = encapsulated.encapsulation();

			// X25519:
			var pkX = pk.getX();
			var pkXKey = pk.getX25519PublicKey();
			byte[] ekX = new byte[32];
			secureRandom.nextBytes(ekX);
			var ctX = X25519.dh(X25519.privateKey(ekX), X25519.basePoint());
			var ssX = X25519.dh(X25519.privateKey(ekX), pkXKey);

			// Combine:
			var ss = combiner(ssM, ssX, ctX, pkX);
			var ct = ArrayUtil.concat(ctM, ctX);
			try {
				return new KEM.Encapsulated(new SecretKeySpec(ss, "Generic"), ct, null);
			} finally {
				Arrays.fill(ss, (byte) 0x00);
				Arrays.fill(ssM, (byte) 0x00);
				Arrays.fill(ssX, (byte) 0x00);
				Arrays.fill(ekX, (byte) 0x00);
			}
		}

		@Override
		public int engineSecretSize() {
			return 32;
		}

		@Override
		public int engineEncapsulationSize() {
			return 1088 + 32; // 1088 bytes for ML-KEM encapsulation + 32 bytes for X25519 encapsulation
		}
	}

	private record XwingDecapsulator(XwingPrivateKey sk) implements DecapsulatorSpi {

		@Override
		public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm) throws DecapsulateException {
			if (encapsulation.length < 1088 + 32) {
				throw new DecapsulateException("Invalid encapsulation length");
			}

			// Derive keys:
			var skBytes = sk.getEncoded();
			XwingKeyPairGeneratorSpi.ExpandedKeys keys;
			try {
				keys = XwingKeyPairGeneratorSpi.expandDecapsulationKey(skBytes);
			} finally {
				Arrays.fill(skBytes, (byte) 0x00);
			}

			// ML-KEM:
			var skM = keys.m().getPrivate();
			var ctM = Arrays.copyOfRange(encapsulation, 0, 1088);
			byte[] ssM;
			try {
				KEM kem = KEM.getInstance("ML-KEM");
				KEM.Decapsulator dec = kem.newDecapsulator(skM);
				ssM = dec.decapsulate(ctM).getEncoded();
			} catch (NoSuchAlgorithmException e) {
				throw new UnsupportedOperationException("ML-KEM algorithm not supported", e);
			} catch (InvalidKeyException e) {
				throw new IllegalArgumentException("Invalid ML-KEM key part of X-Wing public key", e);
			} finally {
				Destroyables.destroyQuietly(skM);
			}

			// X25519:
			var skX = keys.x().getPrivate();
			var ctX = Arrays.copyOfRange(encapsulation, 1088, 1120);
			var publicKeys = XwingPublicKey.createFromKeys(keys.m().getPublic(), keys.x().getPublic());
			var pkX = publicKeys.getX();
			byte[] ssX;
			try {
				ssX = X25519.dh(skX, X25519.publicKey(ctX));
			} finally {
				Destroyables.destroyQuietly(skX);
			}

			// Combine:
			var ss = combiner(ssM, ssX, ctX, pkX);
			try {
				return new SecretKeySpec(ss, "Generic");
			} finally {
				Arrays.fill(ss, (byte) 0x00);
				Arrays.fill(ssM, (byte) 0x00);
				Arrays.fill(ssX, (byte) 0x00);
			}
		}

		@Override
		public int engineSecretSize() {
			return 32; // Size of the shared secret
		}

		@Override
		public int engineEncapsulationSize() {
			return 1088 + 32; // 1088 bytes for ML-KEM encapsulation + 32 bytes for X25519 encapsulation
		}
	}
}
