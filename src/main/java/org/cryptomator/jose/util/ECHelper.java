package org.cryptomator.jose.util;

import com.google.gson.JsonObject;
import org.cryptomator.jose.JoseParseException;

import java.math.BigInteger;
import java.security.AsymmetricKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class ECHelper {

	private static final String EC_ALG = "EC";

	private ECHelper () {
		// Prevent instantiation
	}

	public static ECPublicKey validateKey(ECPublicKey publicKey, ECParameterSpec curveParams) throws IllegalArgumentException {
		validateKey(publicKey.getW(), curveParams);
		return publicKey;
	}

	// validations taken from https://neilmadden.blog/2017/05/17/so-how-do-you-validate-nist-ecdh-public-keys/
	public static void validateKey(ECPoint w, ECParameterSpec curveParams) throws IllegalArgumentException {
		if (curveParams.getCofactor() != 1) {
			throw new IllegalArgumentException("Verifying points on curves with cofactor not supported"); // see "Step 4" in linked post
		}
		EllipticCurve curve = curveParams.getCurve();

		// Step 1: Verify public key is not point at infinity.
		if (ECPoint.POINT_INFINITY.equals(w)) {
			throw new IllegalArgumentException("Invalid EC Key");
		}

		final BigInteger x = w.getAffineX();
		final BigInteger y = w.getAffineY();
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
	}

	public static JsonObject toJwk(ECPublicKey publicKey) {
		var curve = Curve.valueOf(publicKey.getParams().getCurve());
		var x = toUnsignedBytes(publicKey.getW().getAffineX(), curve);
		var y = toUnsignedBytes(publicKey.getW().getAffineY(), curve);

		JsonObject jwk = new JsonObject();
		jwk.addProperty("kty", EC_ALG);
		jwk.addProperty("crv", curve.jwaCrvName);
		jwk.addProperty("x", Base64.getUrlEncoder().withoutPadding().encodeToString(x));
		jwk.addProperty("y", Base64.getUrlEncoder().withoutPadding().encodeToString(y));
		return jwk;
	}

	// fixed-length big-endian unsigned encoding of a coordinate: BigInteger#toByteArray may prepend a zero sign byte, which must be stripped; shorter values are left-padded with zeros
	private static byte[] toUnsignedBytes(BigInteger coordinate, Curve curve) {
		var bytes = coordinate.toByteArray();
		var skip = bytes.length - curve.coordinateByteLength;
		if (skip > 1 || (skip == 1 && bytes[0] != 0x00)) {
			throw new IllegalArgumentException("EC public key coordinates for curve " + curve.jwaCrvName + " exceed expected length of " + curve.coordinateByteLength);
		}
		var result = new byte[curve.coordinateByteLength];
		if (skip > 0) {
			System.arraycopy(bytes, skip, result, 0, result.length);
		} else {
			System.arraycopy(bytes, 0, result, -skip, bytes.length);
		}
		return result;
	}

	public static AsymmetricKey fromJwk(JsonObject jwk) throws JoseParseException {
		if (!jwk.has("kty") || !jwk.get("kty").getAsString().equals(EC_ALG)) {
			throw new JoseParseException("Not an EC key");
		}
		if (!jwk.has("crv")) {
			throw new JoseParseException("EC JWK must contain 'crv', 'x', 'y'");
		}
		String crv = jwk.get("crv").getAsString();
		Curve curve = switch (crv) {
			case "P-256" -> Curve.P256;
			case "P-384" -> Curve.P384;
			case "P-521" -> Curve.P521;
			default -> throw new JoseParseException("Unsupported curve: " + crv);
		};

		KeySpec keySpec;
		if (jwk.has("d")) {
			var s = new BigInteger(1, Base64.getUrlDecoder().decode(jwk.get("d").getAsString()));
			keySpec = new ECPrivateKeySpec(s, curve.getCurveParams());
		} else if (jwk.has("x") && jwk.has("y")) {
			var point = new ECPoint(
					new BigInteger(1, Base64.getUrlDecoder().decode(jwk.get("x").getAsString())),
					new BigInteger(1, Base64.getUrlDecoder().decode(jwk.get("y").getAsString()))
			);
			validateKey(point, curve.getCurveParams());
			keySpec = new ECPublicKeySpec(point, curve.getCurveParams());
		} else {
			throw new JoseParseException("EC JWK must contain 'd' or 'x' and 'y'");
		}
		try {
			var keyFactory = KeyFactory.getInstance(EC_ALG);
			return switch (keySpec) {
				case ECPrivateKeySpec s -> keyFactory.generatePrivate(s);
				case ECPublicKeySpec s -> keyFactory.generatePublic(s);
				default -> throw new IllegalStateException("Unexpected value: " + keySpec);
			};
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("JVM does not support elliptic curves", e);
		} catch (InvalidKeySpecException e) {
			throw new JoseParseException("Invalid curve point", e);
		}
	}
}
