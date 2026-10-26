package org.cryptomator.jose.util;

import com.google.gson.JsonObject;
import org.cryptomator.jose.JoseParseException;

import java.math.BigInteger;
import java.security.KeyPair;
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

	/// Validates a private key scalar: it must lie in `[1, n-1]` for the curve's order `n`
	/// ([SEC 1, Section 3.2.1](https://www.secg.org/sec1-v2.pdf); `0` would yield the point at infinity, values `>= n` alias a smaller scalar).
	///
	/// @param s The private scalar
	/// @param curveParams The curve
	/// @throws IllegalArgumentException if the scalar is out of range
	public static void validateKey(BigInteger s, ECParameterSpec curveParams) throws IllegalArgumentException {
		if (s.signum() <= 0 || s.compareTo(curveParams.getOrder()) >= 0) {
			throw new IllegalArgumentException("Invalid EC private key scalar");
		}
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

	// a required coordinate/scalar member: base64url of exactly the curve's coordinate length, see RFC 7518 Section 6.2.1.2 ("MUST be the full size of a coordinate for the curve")
	private static BigInteger decodeFixedLength(JsonObject jwk, String key, Curve curve) throws JoseParseException {
		final byte[] bytes;
		try {
			bytes = Base64Url.decode(JsonHelper.requireString(jwk, key));
		} catch (IllegalArgumentException e) {
			throw new JoseParseException("EC JWK member '" + key + "' is not base64url", e);
		}
		if (bytes.length != curve.coordinateByteLength) {
			throw new JoseParseException("EC JWK member '" + key + "' must be " + curve.coordinateByteLength + " bytes for " + curve.jwaCrvName + ", but was " + bytes.length);
		}
		return new BigInteger(1, bytes);
	}

	/// Parses an EC JWK ([RFC 7518, Section 6.2](https://www.rfc-editor.org/rfc/rfc7518#section-6.2)) into its key pair.
	///
	/// @param jwk The JWK JSON object with `kty` `EC`
	/// @return The key pair, whose private key is `null` if `d` is absent
	/// @throws JoseParseException if a member is missing, malformed, not of the curve's fixed length, or the key is invalid
	public static KeyPair fromJwk(JsonObject jwk) throws JoseParseException {
		if (!JsonHelper.requireString(jwk, "kty").equals(EC_ALG)) {
			throw new JoseParseException("Not an EC key");
		}
		String crv = JsonHelper.requireString(jwk, "crv");
		Curve curve = switch (crv) {
			case "P-256" -> Curve.P256;
			case "P-384" -> Curve.P384;
			case "P-521" -> Curve.P521;
			default -> throw new JoseParseException("Unsupported curve: " + crv);
		};

		// RFC 7518 Section 6.2.1: x and y are required for every EC JWK, Section 6.2.2: a private key additionally carries d
		final ECPublicKeySpec publicKeySpec;
		final ECPrivateKeySpec privateKeySpec;
		try {
			var point = new ECPoint(decodeFixedLength(jwk, "x", curve), decodeFixedLength(jwk, "y", curve));
			validateKey(point, curve.getCurveParams());
			publicKeySpec = new ECPublicKeySpec(point, curve.getCurveParams());
			if (jwk.has("d")) {
				var s = decodeFixedLength(jwk, "d", curve);
				validateKey(s, curve.getCurveParams());
				privateKeySpec = new ECPrivateKeySpec(s, curve.getCurveParams()); // not checked for consistency with the public point
			} else {
				privateKeySpec = null;
			}
		} catch (IllegalArgumentException e) {
			throw new JoseParseException("Invalid EC key", e);
		}
		try {
			var keyFactory = KeyFactory.getInstance(EC_ALG);
			var publicKey = keyFactory.generatePublic(publicKeySpec);
			var privateKey = privateKeySpec == null ? null : keyFactory.generatePrivate(privateKeySpec);
			return new KeyPair(publicKey, privateKey);
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("JVM does not support elliptic curves", e);
		} catch (InvalidKeySpecException e) {
			throw new JoseParseException("Invalid curve point", e);
		}
	}
}
