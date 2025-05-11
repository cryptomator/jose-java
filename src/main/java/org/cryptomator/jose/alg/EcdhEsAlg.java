package org.cryptomator.jose.alg;

import com.google.gson.JsonObject;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.util.Destroyables;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public final class EcdhEsAlg extends AbstractAlg {

	private static final String EC_ALG = "EC";

	public enum Type {
		ECDH_ES_A256KW("ECDH-ES+A256KW", "AESWrap", "AES",32),
		;

		private final String jwaAlgName;
		private final String jcaKwAlgName;
		private final String jcaKeyAlgName;
		private final int keyLength;

		Type(String jwaAlgName, String jcaKwAlgName, String jcaKeyAlgName, int keyLength) {
			this.jwaAlgName = jwaAlgName;
			this.jcaKwAlgName = jcaKwAlgName;
			this.jcaKeyAlgName = jcaKeyAlgName;
			this.keyLength = keyLength;
		}
	}

	public enum Curve {
		P384("P-384", "secp384r1"),
		;

		private final String jwaCrvName;
		private final String jcaCurveName;

		Curve(String jwaCrvName, String jcaCurveName) {
			this.jwaCrvName = jwaCrvName;
			this.jcaCurveName = jcaCurveName;
		}

		public KeyPair generateKeyPair() {
			try {
				var keyGen = KeyPairGenerator.getInstance(EC_ALG);
				keyGen.initialize(new ECGenParameterSpec(jcaCurveName));
				return keyGen.generateKeyPair();
			} catch (NoSuchAlgorithmException e) {
				throw new UnsupportedOperationException("JVM does not support elliptic curves", e);
			} catch (InvalidAlgorithmParameterException e) {
				throw new AssertionError("ECGenParameterSpec deemed unappropriate by EC key pair generator", e);
			}
		}

		public ECParameterSpec getCurveParams() {
			try {
				AlgorithmParameters parameters = AlgorithmParameters.getInstance(EC_ALG);
				parameters.init(new ECGenParameterSpec(jcaCurveName));
				return parameters.getParameterSpec(ECParameterSpec.class);
			} catch (NoSuchAlgorithmException e) {
				throw new UnsupportedOperationException("JVM does not support elliptic curves", e);
			} catch (InvalidParameterSpecException e) {
				throw new AssertionError("ECGenParameterSpec deemed unappropriate by EC algorithm parameter provider", e);
			}
		}

//		public ECPublicKey importPublicKey(X509EncodedKeySpec keySpec) throws InvalidKeySpecException {
//			try {
//				var factory = KeyFactory.getInstance(EC_ALG);
//				if (factory.generatePublic(keySpec) instanceof ECPublicKey k) {
//					return validateKey(k, getCurveParams());
//				} else {
//					throw new AssertionError("Key imported by EC key factory not an EC key");
//				}
//			} catch (NoSuchAlgorithmException e) {
//				throw new UnsupportedOperationException("JVM does not support elliptic curves", e);
//			}
//		}
	}

	private final Type type;
	private final Curve curve;
	private final ECPublicKey publicKey;
	private final ECPrivateKey privateKey;

	public EcdhEsAlg(Type type, Curve curve, ECPublicKey publicKey, ECPrivateKey privateKey) {
		this.type = type;
		this.curve = curve;
		this.publicKey = publicKey == null ? null : validateKey(publicKey, curve.getCurveParams());
		this.privateKey = privateKey;
	}

	@Override
	public String name() {
		return "ECDH-ES+A256KW";
	}

	@Override
	public byte[] decrypt(JsonObject combinedHeader, byte[] encryptedKey) throws JoseDecryptException {
		if (privateKey == null) {
			throw new IllegalStateException("No private key available for decryption.");
		}
		return new byte[0];
	}

	@Override
	public EncryptionResult encrypt(JsonObject combinedHeader, byte[] cek) {
		if (publicKey == null) {
			throw new IllegalStateException("No public key available for encryption.");
		}

		// import static public key:
//		final ECPublicKey publicKey;
//		try {
//			publicKey = curve.importPublicKey(new X509EncodedKeySpec(cek));
//		} catch (InvalidKeySpecException e) {
//			throw new IllegalArgumentException(e); // TODO: better throw JoseEncryptException?
//		}

		// generate ephemeral key pair:
		var keyPair = curve.generateKeyPair();
		final ECPrivateKey ephPrivateKey;
		final ECPublicKey ephPublicKey;
		if (keyPair.getPrivate() instanceof ECPrivateKey priv
				&& keyPair.getPublic() instanceof ECPublicKey pub) {
			ephPrivateKey = priv;
			ephPublicKey = pub;
		} else {
			throw new AssertionError("Key generated by EC key generator not an EC key");
		}

		// derive shared secret using ECDH-ES:
		final byte[] sharedSecret;
		try {
			var keyAgreement = KeyAgreement.getInstance("ECDH");
			keyAgreement.init(ephPrivateKey);
			keyAgreement.doPhase(publicKey, true);
			sharedSecret = keyAgreement.generateSecret();
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("JVM does not support ECDH", e);
		} catch (InvalidKeyException e) {
			throw new IllegalStateException("Unsuitable key", e);
		} finally {
			Destroyables.destroyQuietly(ephPrivateKey);
		}

		// derive wrapping key using KDF:
		final SecretKey wrappingKey;
		try {
			var wrappingKeyBytes = deriveKey(sharedSecret, combinedHeader);
			wrappingKey = new SecretKeySpec(wrappingKeyBytes, type.jcaKeyAlgName);
		} finally {
			Arrays.fill(sharedSecret, (byte) 0x00);
		}

		// wrap using AES key wrap:
		final byte[] encryptedKey;
		try {
			SecretKey toBeWrapped = new SecretKeySpec(cek, "AES");
			Cipher cipher = Cipher.getInstance(type.jcaKwAlgName);
			cipher.init(Cipher.WRAP_MODE, wrappingKey);
			encryptedKey = cipher.wrap(toBeWrapped);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new UnsupportedOperationException("JVM does not support " + type.jcaKwAlgName, e);
		} catch (InvalidKeyException e) {
			throw new IllegalStateException("Unsuitable wrapping key", e);
		} catch (IllegalBlockSizeException e) {
			throw new IllegalStateException("CEK not multiple of block size", e);
		}

		// assemble header
		JsonObject perRecipientHeader = new JsonObject();
		perRecipientHeader.addProperty("alg", type.jwaAlgName);
		perRecipientHeader.add("epk", toJwk(ephPublicKey));
//		perRecipientHeader.addProperty("apu", combinedHeader.get("apu").getAsString());
//		perRecipientHeader.addProperty("apv", combinedHeader.get("apv").getAsString());
		return new EncryptionResult(encryptedKey, perRecipientHeader);
	}

	private JsonObject toJwk(ECPublicKey publicKey) {
		JsonObject jwk = new JsonObject();
		jwk.addProperty("kty", EC_ALG);
		jwk.addProperty("crv", curve.jwaCrvName);
		jwk.addProperty("x", Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getW().getAffineX().toByteArray()));
		jwk.addProperty("y", Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getW().getAffineY().toByteArray()));
		return jwk;
	}

	private byte[] deriveKey(byte[] sharedSecret, JsonObject combinedHeader) {
		var algorithmId = type.jwaAlgName.getBytes(StandardCharsets.US_ASCII); // TODO: if alg is "ECDH-ES" (without key wrap), use "enc" value from header
		var partyUInfo = combinedHeader.has("apu") ? Base64.getUrlDecoder().decode(combinedHeader.get("apu").getAsString()) : new byte[0];
		var partyVInfo = combinedHeader.has("apv") ? Base64.getUrlDecoder().decode(combinedHeader.get("apu").getAsString()) : new byte[0];
		var suppPubInfo = type.keyLength;
		var suppPrivInfo = new byte[0];
		ByteBuffer otherInfo = ByteBuffer.allocate(Integer.BYTES + algorithmId.length
				+ Integer.BYTES + partyUInfo.length
				+ Integer.BYTES + partyVInfo.length
				+ Integer.BYTES
				+ suppPrivInfo.length
		);
		otherInfo.putInt(algorithmId.length).put(algorithmId);
		otherInfo.putInt(partyUInfo.length).put(partyUInfo);
		otherInfo.putInt(partyVInfo.length).put(partyVInfo);
		otherInfo.putInt(suppPubInfo);
		otherInfo.put(suppPrivInfo);
		return ConcatKDF.sha256().kdf(sharedSecret, type.keyLength, otherInfo.array());
	}

	// validations taken from https://neilmadden.blog/2017/05/17/so-how-do-you-validate-nist-ecdh-public-keys/
	private static ECPublicKey validateKey(ECPublicKey publicKey, ECParameterSpec curveParams) {
		if (curveParams.getCofactor() != 1) {
			throw new IllegalArgumentException("Verifying points on curves with cofactor not supported"); // see "Step 4" in linked post
		}
		EllipticCurve curve = curveParams.getCurve();

		// Step 1: Verify public key is not point at infinity.
		if (ECPoint.POINT_INFINITY.equals(publicKey.getW())) {
			throw new IllegalArgumentException("Invalid EC Key");
		}

		final BigInteger x = publicKey.getW().getAffineX();
		final BigInteger y = publicKey.getW().getAffineY();
		final BigInteger p = ((ECFieldFp) curve.getField()).getP();

		// Step 2: Verify x and y are in range [0,p-1]
		if (x.compareTo(BigInteger.ZERO) < 0 || x.compareTo(p) >= 0) {
			throw new IllegalArgumentException("Invalid EC Key");
		}
		if (y.compareTo(BigInteger.ZERO) < 0 || y.compareTo(p) >= 0) {
			throw new IllegalArgumentException("Invalid EC Key");
		}

		// Step 3: Verify that y^2 == x^3 + ax + b (mod p)
		final BigInteger a = curve.getA();
		final BigInteger b = curve.getB();
		final BigInteger ySquared = y.modPow(BigInteger.valueOf(2), p);
		final BigInteger xCubedPlusAXPlusB = x.modPow(BigInteger.valueOf(3), p).add(a.multiply(x)).add(b).mod(p);
		if (!ySquared.equals(xCubedPlusAXPlusB)) {
			throw new IllegalArgumentException("Invalid EC Key");
		}

		return publicKey;
	}


}
