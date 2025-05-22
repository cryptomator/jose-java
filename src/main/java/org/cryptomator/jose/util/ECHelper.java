package org.cryptomator.jose.util;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

public class ECHelper {

	private ECHelper () {
		// Prevent instantiation
	}

	// validations taken from https://neilmadden.blog/2017/05/17/so-how-do-you-validate-nist-ecdh-public-keys/
	public static ECPublicKey validateKey(ECPublicKey publicKey, ECParameterSpec curveParams) throws IllegalArgumentException {
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
