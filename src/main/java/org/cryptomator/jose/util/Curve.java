package org.cryptomator.jose.util;

import java.security.AlgorithmParameters;
import java.security.AsymmetricKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public enum Curve {
	P256("P-256", "secp256r1"),
	P384("P-384", "secp384r1"),
	P521("P-521", "secp521r1"),
	;

	private static final String EC_ALG = "EC";

	public final String jwaCrvName;
	public final String jcaCurveName;

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

	public <T extends ECKey> T ensureSameCurve(T key) { // TODO: add @Nullable annotation?
		if (key == null) {
			return null;
		} else if (getCurveParams().getCurve().equals(key.getParams().getCurve())) {
			return key;
		} else {
			throw new IllegalArgumentException("Not a " + jwaCrvName + " key");
		}
	}

	public ECPublicKey validate(ECPublicKey publicKey) throws IllegalArgumentException {
		return ECHelper.validateKey(ensureSameCurve(publicKey), getCurveParams());
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
