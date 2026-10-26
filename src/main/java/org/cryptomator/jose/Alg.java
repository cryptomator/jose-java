package org.cryptomator.jose;

import org.cryptomator.jose.alg.AesKwAlg;
import org.cryptomator.jose.alg.EcdhEsAlg;
import org.cryptomator.jose.alg.HPKEIntegratedAlg;
import org.cryptomator.jose.alg.HPKEKeyEncryptionAlg;
import org.cryptomator.jose.alg.Pbes2Alg;
import org.cryptomator.jose.hpke.HPKE;
import org.cryptomator.jose.hpke.XwingProvider;
import org.cryptomator.jose.util.Curve;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/// A JWE algorithm, identified by its `alg` header value. It is split by direction into [EncryptionAlg] and [DecryptionAlg], and by JWE Key Management Mode
/// into key management (protecting a content encryption key, [RFC 7518 Section 4](https://www.rfc-editor.org/rfc/rfc7518#section-4)) and Integrated Encryption
/// ([draft-ietf-jose-hpke-encrypt Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5), where HPKE encrypts the payload directly and there is no CEK).
public sealed interface Alg permits DecryptionAlg, EncryptionAlg {

	/// The `alg` (algorithm) header parameter value identifying this algorithm.
	String name();

	// FACTORY METHODS

	// TODO: which algorithms do we want to expose here?

	/// Key Encryption with `A256KW` ([RFC 7518, Section 4.4](https://www.rfc-editor.org/rfc/rfc7518#section-4.4)) using a caller-supplied key encryption key,
	/// e.g. one derived from a password with a KDF of the caller's choice. The returned instance serves both directions.
	///
	/// @param kek A 256-bit AES key, which remains owned (and eventually destroyed) by the caller
	/// @return An algorithm instance usable for encryption and decryption
	/// @throws IllegalArgumentException if the key is not a 256-bit AES key
	static SymmetricKeyAlg a256kw(SecretKey kek) {
		return new AesKwAlg(kek);
	}

	/// Key Encryption with `PBES2-HS512+A256KW` ([RFC 7518, Section 4.8](https://www.rfc-editor.org/rfc/rfc7518#section-4.8)) using a caller-supplied password
	/// and the default PBKDF2 iteration count ({@value Pbes2Alg#DEFAULT_P2C}). The returned instance serves both directions; on decryption, the iteration count is read from the `p2c` header.
	///
	/// @param password The password, which remains owned (and eventually wiped) by the caller
	/// @return An algorithm instance usable for encryption and decryption
	/// @see Pbes2Alg#MAX_P2C the cumulative PBKDF2 budget per decrypt call, and why `kid`-targeted decryption is preferable for multi-recipient tokens
	static SymmetricKeyAlg pbes2(char[] password) {
		return new Pbes2Alg(Pbes2Alg.Type.PBES2_HS512_A256KW, password, Pbes2Alg.DEFAULT_P2C);
	}

	/// Key Encryption with `PBES2-HS512+A256KW` ([RFC 7518, Section 4.8](https://www.rfc-editor.org/rfc/rfc7518#section-4.8)) using a caller-supplied password
	/// and a custom PBKDF2 iteration count. The returned instance serves both directions; on decryption, the iteration count is read from the `p2c` header.
	///
	/// Prefer [#pbes2(char\[\])] unless you have a reason to deviate from the default.
	///
	/// @param password The password, which remains owned (and eventually wiped) by the caller
	/// @param iterationCount The PBKDF2 iteration count used for encryption, between {@value Pbes2Alg#MIN_P2C} and {@value Pbes2Alg#MAX_P2C} (larger counts would produce tokens this library refuses to decrypt)
	/// @return An algorithm instance usable for encryption and decryption
	/// @throws IllegalArgumentException if the iteration count is below the minimum of {@value Pbes2Alg#MIN_P2C} recommended by [RFC 7518, Section 4.8.1.2](https://www.rfc-editor.org/rfc/rfc7518#section-4.8.1.2) or above {@value Pbes2Alg#MAX_P2C}
	static SymmetricKeyAlg pbes2(char[] password, int iterationCount) {
		return new Pbes2Alg(Pbes2Alg.Type.PBES2_HS512_A256KW, password, iterationCount);
	}

	/// Key Encryption with `ECDH-ES+A256KW` ([RFC 7518, Section 4.6](https://www.rfc-editor.org/rfc/rfc7518#section-4.6)) on the key's curve (P-256, P-384 or P-521).
	///
	/// @param privateKey The recipient's EC private key
	/// @return The decryption algorithm
	/// @throws IllegalArgumentException if the key is not an EC key on a supported curve
	static DecryptionAlg ecdhEs(PrivateKey privateKey) {
		if (!(privateKey instanceof ECPrivateKey k)) {
			throw new IllegalArgumentException("Private key must be an instance of ECPrivateKey");
		}
		var curve = Curve.valueOf(k.getParams().getCurve());
		return new EcdhEsAlg(EcdhEsAlg.Type.ECDH_ES_A256KW, curve, null, k);
	}

	/// Key Encryption with `ECDH-ES+A256KW` ([RFC 7518, Section 4.6](https://www.rfc-editor.org/rfc/rfc7518#section-4.6)) on the key's curve (P-256, P-384 or P-521).
	///
	/// @param publicKey The recipient's EC public key
	/// @return The encryption algorithm
	/// @throws IllegalArgumentException if the key is not an EC key on a supported curve, or not a valid point on that curve
	static KeyEncryptionAlg ecdhEs(PublicKey publicKey) {
		if (!(publicKey instanceof ECPublicKey k)) {
			throw new IllegalArgumentException("Public key must be an instance of ECPublicKey");
		}
		var curve = Curve.valueOf(k.getParams().getCurve());
		return new EcdhEsAlg(EcdhEsAlg.Type.ECDH_ES_A256KW, curve, curve.validate(k), null);
	}

	/// Key Encryption with `ECDH-ES+A256KW` using the public key of an EC JWK, whose `alg` parameter, if present, must be `ECDH-ES+A256KW`.
	///
	/// @throws IllegalArgumentException if the JWK's `alg` names another algorithm, or the key is not on the expected curve
	static KeyEncryptionAlg ecdhEs(JWK.Public jwk) {
		return ecdhEs(requireAlg(jwk, "ECDH-ES+A256KW").publicKey());
	}

	/// Key Encryption with `ECDH-ES+A256KW` using the private key of an EC JWK, whose `alg` parameter, if present, must be `ECDH-ES+A256KW`.
	///
	/// @throws IllegalArgumentException if the JWK's `alg` names another algorithm, or the key is not on the expected curve
	static DecryptionAlg ecdhEs(JWK.Private jwk) {
		return ecdhEs(requireAlg(jwk, "ECDH-ES+A256KW").privateKey());
	}

	/// Integrated Encryption with `HPKE-0`, as defined in [draft-ietf-jose-hpke-encrypt, Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5)
	static IntegratedEncryptionAlg hpke0(PublicKey publicKey) {
		if (!(publicKey instanceof ECPublicKey k)) {
			throw new IllegalArgumentException("Public key must be an instance of ECPublicKey");
		}
		return new HPKEIntegratedAlg(HPKE.hpke0(), Curve.P256.ensureSameCurve(k), null);
	}

	/// Integrated Encryption with `HPKE-0`, as defined in [draft-ietf-jose-hpke-encrypt, Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5)
	static DecryptionAlg hpke0(PrivateKey privateKey) {
		if (!(privateKey instanceof ECPrivateKey k)) {
			throw new IllegalArgumentException("Private key must be an instance of ECPrivateKey");
		}
		return new HPKEIntegratedAlg(HPKE.hpke0(), null, Curve.P256.ensureSameCurve(k));
	}

	/// Integrated Encryption with `HPKE-0` using the public key of an EC JWK, whose `alg` parameter, if present, must be `HPKE-0`.
	///
	/// @throws IllegalArgumentException if the JWK's `alg` names another algorithm, or the key is not on the expected curve
	static IntegratedEncryptionAlg hpke0(JWK.Public jwk) {
		return hpke0(requireAlg(jwk, "HPKE-0").publicKey());
	}

	/// Integrated Encryption with `HPKE-0` using the private key of an EC JWK, whose `alg` parameter, if present, must be `HPKE-0`.
	///
	/// @throws IllegalArgumentException if the JWK's `alg` names another algorithm, or the key is not on the expected curve
	static DecryptionAlg hpke0(JWK.Private jwk) {
		return hpke0(requireAlg(jwk, "HPKE-0").privateKey());
	}

	/// Integrated Encryption with `HPKE-1`, as defined in [draft-ietf-jose-hpke-encrypt, Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5)
	static IntegratedEncryptionAlg hpke1(PublicKey publicKey) {
		if (!(publicKey instanceof ECPublicKey k)) {
			throw new IllegalArgumentException("Public key must be an instance of ECPublicKey");
		}
		return new HPKEIntegratedAlg(HPKE.hpke1(), Curve.P384.ensureSameCurve(k), null);
	}

	/// Integrated Encryption with `HPKE-1`, as defined in [draft-ietf-jose-hpke-encrypt, Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5)
	static DecryptionAlg hpke1(PrivateKey privateKey) {
		if (!(privateKey instanceof ECPrivateKey k)) {
			throw new IllegalArgumentException("Private key must be an instance of ECPrivateKey");
		}
		return new HPKEIntegratedAlg(HPKE.hpke1(), null, Curve.P384.ensureSameCurve(k));
	}

	/// Integrated Encryption with `HPKE-1` using the public key of an EC JWK, whose `alg` parameter, if present, must be `HPKE-1`.
	///
	/// @throws IllegalArgumentException if the JWK's `alg` names another algorithm, or the key is not on the expected curve
	static IntegratedEncryptionAlg hpke1(JWK.Public jwk) {
		return hpke1(requireAlg(jwk, "HPKE-1").publicKey());
	}

	/// Integrated Encryption with `HPKE-1` using the private key of an EC JWK, whose `alg` parameter, if present, must be `HPKE-1`.
	///
	/// @throws IllegalArgumentException if the JWK's `alg` names another algorithm, or the key is not on the expected curve
	static DecryptionAlg hpke1(JWK.Private jwk) {
		return hpke1(requireAlg(jwk, "HPKE-1").privateKey());
	}

	/// Integrated Encryption with `HPKE-2`, as defined in [draft-ietf-jose-hpke-encrypt, Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5)
	static IntegratedEncryptionAlg hpke2(PublicKey publicKey) {
		if (!(publicKey instanceof ECPublicKey k)) {
			throw new IllegalArgumentException("Public key must be an instance of ECPublicKey");
		}
		return new HPKEIntegratedAlg(HPKE.hpke2(), Curve.P521.ensureSameCurve(k), null);
	}

	/// Integrated Encryption with `HPKE-2`, as defined in [draft-ietf-jose-hpke-encrypt, Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5)
	static DecryptionAlg hpke2(PrivateKey privateKey) {
		if (!(privateKey instanceof ECPrivateKey k)) {
			throw new IllegalArgumentException("Private key must be an instance of ECPrivateKey");
		}
		return new HPKEIntegratedAlg(HPKE.hpke2(), null, Curve.P521.ensureSameCurve(k));
	}

	/// Integrated Encryption with `HPKE-2` using the public key of an EC JWK, whose `alg` parameter, if present, must be `HPKE-2`.
	///
	/// @throws IllegalArgumentException if the JWK's `alg` names another algorithm, or the key is not on the expected curve
	static IntegratedEncryptionAlg hpke2(JWK.Public jwk) {
		return hpke2(requireAlg(jwk, "HPKE-2").publicKey());
	}

	/// Integrated Encryption with `HPKE-2` using the private key of an EC JWK, whose `alg` parameter, if present, must be `HPKE-2`.
	///
	/// @throws IllegalArgumentException if the JWK's `alg` names another algorithm, or the key is not on the expected curve
	static DecryptionAlg hpke2(JWK.Private jwk) {
		return hpke2(requireAlg(jwk, "HPKE-2").privateKey());
	}

	/// Integrated Encryption with `HPKE-9`, as defined in [draft-ietf-jose-hpke-pq-pqt](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-pq-pqt/)
	static IntegratedEncryptionAlg hpke9(PublicKey publicKey) {
		return new HPKEIntegratedAlg(HPKE.hpke9(), asXwingPublicKey(publicKey), null);
	}

	/// Integrated Encryption with `HPKE-9`, as defined in [draft-ietf-jose-hpke-pq-pqt](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-pq-pqt/)
	static DecryptionAlg hpke9(PrivateKey privateKey) {
		return new HPKEIntegratedAlg(HPKE.hpke9(), null, asXwingPrivateKey(privateKey));
	}

	/// Integrated Encryption with `HPKE-9` using the public key of an AKP JWK, which must be bound to `HPKE-9` by its `alg` parameter.
	///
	/// @throws IllegalArgumentException if the JWK's `alg` is not `HPKE-9`
	static IntegratedEncryptionAlg hpke9(JWK.Public jwk) {
		return hpke9(requireAlg(jwk, "HPKE-9").publicKey());
	}

	/// Integrated Encryption with `HPKE-9` using the private key of an AKP JWK, which must be bound to `HPKE-9` by its `alg` parameter.
	///
	/// @throws IllegalArgumentException if the JWK's `alg` is not `HPKE-9`
	static DecryptionAlg hpke9(JWK.Private jwk) {
		return hpke9(requireAlg(jwk, "HPKE-9").privateKey());
	}

	/// Key Encryption with `HPKE-0-KE`, as defined in [draft-ietf-jose-hpke-encrypt, Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6)
	static KeyEncryptionAlg hpke0Ke(PublicKey publicKey) {
		if (!(publicKey instanceof ECPublicKey k)) {
			throw new IllegalArgumentException("Public key must be an instance of ECPublicKey");
		}
		return new HPKEKeyEncryptionAlg(HPKE.hpke0(), Curve.P256.ensureSameCurve(k), null);
	}

	/// Key Encryption with `HPKE-0-KE`, as defined in [draft-ietf-jose-hpke-encrypt, Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6)
	static DecryptionAlg hpke0Ke(PrivateKey privateKey) {
		if (!(privateKey instanceof ECPrivateKey k)) {
			throw new IllegalArgumentException("Private key must be an instance of ECPrivateKey");
		}
		return new HPKEKeyEncryptionAlg(HPKE.hpke0(), null, Curve.P256.ensureSameCurve(k));
	}

	/// Key Encryption with `HPKE-0-KE` using the public key of an EC JWK, whose `alg` parameter, if present, must be `HPKE-0-KE`.
	///
	/// @throws IllegalArgumentException if the JWK's `alg` names another algorithm, or the key is not on the expected curve
	static KeyEncryptionAlg hpke0Ke(JWK.Public jwk) {
		return hpke0Ke(requireAlg(jwk, "HPKE-0-KE").publicKey());
	}

	/// Key Encryption with `HPKE-0-KE` using the private key of an EC JWK, whose `alg` parameter, if present, must be `HPKE-0-KE`.
	///
	/// @throws IllegalArgumentException if the JWK's `alg` names another algorithm, or the key is not on the expected curve
	static DecryptionAlg hpke0Ke(JWK.Private jwk) {
		return hpke0Ke(requireAlg(jwk, "HPKE-0-KE").privateKey());
	}

	/// Key Encryption with `HPKE-1-KE`, as defined in [draft-ietf-jose-hpke-encrypt, Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6)
	static KeyEncryptionAlg hpke1Ke(PublicKey publicKey) {
		if (!(publicKey instanceof ECPublicKey k)) {
			throw new IllegalArgumentException("Public key must be an instance of ECPublicKey");
		}
		return new HPKEKeyEncryptionAlg(HPKE.hpke1(), Curve.P384.ensureSameCurve(k), null);
	}

	/// Key Encryption with `HPKE-1-KE`, as defined in [draft-ietf-jose-hpke-encrypt, Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6)
	static DecryptionAlg hpke1Ke(PrivateKey privateKey) {
		if (!(privateKey instanceof ECPrivateKey k)) {
			throw new IllegalArgumentException("Private key must be an instance of ECPrivateKey");
		}
		return new HPKEKeyEncryptionAlg(HPKE.hpke1(), null, Curve.P384.ensureSameCurve(k));
	}

	/// Key Encryption with `HPKE-1-KE` using the public key of an EC JWK, whose `alg` parameter, if present, must be `HPKE-1-KE`.
	///
	/// @throws IllegalArgumentException if the JWK's `alg` names another algorithm, or the key is not on the expected curve
	static KeyEncryptionAlg hpke1Ke(JWK.Public jwk) {
		return hpke1Ke(requireAlg(jwk, "HPKE-1-KE").publicKey());
	}

	/// Key Encryption with `HPKE-1-KE` using the private key of an EC JWK, whose `alg` parameter, if present, must be `HPKE-1-KE`.
	///
	/// @throws IllegalArgumentException if the JWK's `alg` names another algorithm, or the key is not on the expected curve
	static DecryptionAlg hpke1Ke(JWK.Private jwk) {
		return hpke1Ke(requireAlg(jwk, "HPKE-1-KE").privateKey());
	}

	/// Key Encryption with `HPKE-2-KE`, as defined in [draft-ietf-jose-hpke-encrypt, Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6)
	static KeyEncryptionAlg hpke2Ke(PublicKey publicKey) {
		if (!(publicKey instanceof ECPublicKey k)) {
			throw new IllegalArgumentException("Public key must be an instance of ECPublicKey");
		}
		return new HPKEKeyEncryptionAlg(HPKE.hpke2(), Curve.P521.ensureSameCurve(k), null);
	}

	/// Key Encryption with `HPKE-2-KE`, as defined in [draft-ietf-jose-hpke-encrypt, Section 6](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-6)
	static DecryptionAlg hpke2Ke(PrivateKey privateKey) {
		if (!(privateKey instanceof ECPrivateKey k)) {
			throw new IllegalArgumentException("Private key must be an instance of ECPrivateKey");
		}
		return new HPKEKeyEncryptionAlg(HPKE.hpke2(), null, Curve.P521.ensureSameCurve(k));
	}

	/// Key Encryption with `HPKE-2-KE` using the public key of an EC JWK, whose `alg` parameter, if present, must be `HPKE-2-KE`.
	///
	/// @throws IllegalArgumentException if the JWK's `alg` names another algorithm, or the key is not on the expected curve
	static KeyEncryptionAlg hpke2Ke(JWK.Public jwk) {
		return hpke2Ke(requireAlg(jwk, "HPKE-2-KE").publicKey());
	}

	/// Key Encryption with `HPKE-2-KE` using the private key of an EC JWK, whose `alg` parameter, if present, must be `HPKE-2-KE`.
	///
	/// @throws IllegalArgumentException if the JWK's `alg` names another algorithm, or the key is not on the expected curve
	static DecryptionAlg hpke2Ke(JWK.Private jwk) {
		return hpke2Ke(requireAlg(jwk, "HPKE-2-KE").privateKey());
	}

	/// Key Encryption with `HPKE-9-KE`, as defined in [draft-ietf-jose-hpke-pq-pqt](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-pq-pqt/)
	static KeyEncryptionAlg hpke9Ke(PublicKey publicKey) {
		return new HPKEKeyEncryptionAlg(HPKE.hpke9(), asXwingPublicKey(publicKey), null);
	}

	/// Key Encryption with `HPKE-9-KE`, as defined in [draft-ietf-jose-hpke-pq-pqt](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-pq-pqt/)
	static DecryptionAlg hpke9Ke(PrivateKey privateKey) {
		return new HPKEKeyEncryptionAlg(HPKE.hpke9(), null, asXwingPrivateKey(privateKey));
	}

	/// Key Encryption with `HPKE-9-KE` using the public key of an AKP JWK, which must be bound to `HPKE-9-KE` by its `alg` parameter.
	///
	/// @throws IllegalArgumentException if the JWK's `alg` is not `HPKE-9-KE`
	static KeyEncryptionAlg hpke9Ke(JWK.Public jwk) {
		return hpke9Ke(requireAlg(jwk, "HPKE-9-KE").publicKey());
	}

	/// Key Encryption with `HPKE-9-KE` using the private key of an AKP JWK, which must be bound to `HPKE-9-KE` by its `alg` parameter.
	///
	/// @throws IllegalArgumentException if the JWK's `alg` is not `HPKE-9-KE`
	static DecryptionAlg hpke9Ke(JWK.Private jwk) {
		return hpke9Ke(requireAlg(jwk, "HPKE-9-KE").privateKey());
	}

	/// The decryption algorithm an AKP or EC JWK is bound to by its `alg` parameter, so that a recipient can decrypt without naming the algorithm in code:
	/// `JWE.parse(token).decrypt(Alg.forJwk(JWK.parsePrivate(json)))`.
	///
	/// @param jwk A private JWK with an `alg` parameter
	/// @return The decryption algorithm for that `alg`, holding the JWK's private key
	/// @throws IllegalArgumentException if the JWK has no `alg`, or names an algorithm this library does not implement
	static DecryptionAlg forJwk(JWK.Private jwk) {
		var alg = jwk.alg().orElseThrow(() -> new IllegalArgumentException("JWK has no alg parameter"));
		return switch (alg) {
			case "ECDH-ES+A256KW" -> ecdhEs(jwk);
			case "HPKE-0" -> hpke0(jwk);
			case "HPKE-1" -> hpke1(jwk);
			case "HPKE-2" -> hpke2(jwk);
			case "HPKE-9" -> hpke9(jwk);
			case "HPKE-0-KE" -> hpke0Ke(jwk);
			case "HPKE-1-KE" -> hpke1Ke(jwk);
			case "HPKE-2-KE" -> hpke2Ke(jwk);
			case "HPKE-9-KE" -> hpke9Ke(jwk);
			default -> throw new IllegalArgumentException("Unsupported JWK alg: " + alg);
		};
	}

	// RFC 7517 Section 4.4: alg identifies the algorithm intended for use with the key; a key published for one HPKE mode must not be used in the other
	private static <T extends JWK> T requireAlg(T jwk, String alg) {
		if (!alg.equals(jwk.alg().orElse(alg))) {
			throw new IllegalArgumentException("JWK is bound to alg '" + jwk.alg().get() + "', not '" + alg + "'");
		}
		return jwk;
	}

	private static PublicKey asXwingPublicKey(PublicKey publicKey) {
		try {
			var kf = KeyFactory.getInstance("X-Wing", XwingProvider.INSTANCE);
			return (PublicKey) kf.translateKey(publicKey);
		} catch (NoSuchAlgorithmException e) {
			throw new AssertionError("Custom X-Wing provider must support X-Wing key factory", e);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Not an X-Wing public key.", e);
		}
	}

	private static PrivateKey asXwingPrivateKey(PrivateKey privateKey) {
		try {
			var kf = KeyFactory.getInstance("X-Wing", XwingProvider.INSTANCE);
			return (PrivateKey) kf.translateKey(privateKey);
		} catch (NoSuchAlgorithmException e) {
			throw new AssertionError("Custom X-Wing provider must support X-Wing key factory", e);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Not an X-Wing private key.", e);
		}
	}

}
