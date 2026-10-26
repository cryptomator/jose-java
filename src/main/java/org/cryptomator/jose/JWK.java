package org.cryptomator.jose;

import com.google.gson.JsonObject;
import org.cryptomator.jose.hpke.XwingProvider;
import org.cryptomator.jose.hpke.XwingSeedParameterSpec;
import org.cryptomator.jose.util.Base64Url;
import org.cryptomator.jose.util.ECHelper;
import org.cryptomator.jose.util.JsonHelper;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/// A parsed JSON Web Key ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)): the key material plus the `alg` and `kid` parameters a caller needs to pick
/// and bind the right algorithm. [Private] JWKs always carry their public key as well, so one parse result serves both directions.
///
/// Supported key types ([IANA JWK Types](https://www.iana.org/assignments/jose/jose.xhtml#web-key-types)): `EC` on P-256/P-384/P-521 and `AKP`
/// ([RFC 9964](https://www.rfc-editor.org/rfc/rfc9964)) for the X-Wing based `HPKE-9`/`HPKE-9-KE` algorithms.
public sealed interface JWK permits JWK.Public, JWK.Private {

	/// A JWK holding only public key material.
	///
	/// @param kty The `kty` parameter
	/// @param alg The `alg` parameter, if present (always present for `AKP`)
	/// @param kid The `kid` parameter, if present
	/// @param publicKey The public key
	record Public(String kty, Optional<String> alg, Optional<String> kid, PublicKey publicKey) implements JWK {

		public Public {
			Objects.requireNonNull(kty);
			Objects.requireNonNull(alg);
			Objects.requireNonNull(kid);
			Objects.requireNonNull(publicKey);
		}

	}

	/// A JWK holding a private key and its public key.
	///
	/// @param kty The `kty` parameter
	/// @param alg The `alg` parameter, if present (always present for `AKP`)
	/// @param kid The `kid` parameter, if present
	/// @param publicKey The public key
	/// @param privateKey The private key
	record Private(String kty, Optional<String> alg, Optional<String> kid, PublicKey publicKey, PrivateKey privateKey) implements JWK {

		public Private {
			Objects.requireNonNull(kty);
			Objects.requireNonNull(alg);
			Objects.requireNonNull(kid);
			Objects.requireNonNull(publicKey);
			Objects.requireNonNull(privateKey);
		}

		/// @return The same JWK without its private key
		public Public toPublic() {
			return new Public(kty, alg, kid, publicKey);
		}

		@Override
		public String toString() {
			return "Private[kty=" + kty + ", alg=" + alg + ", kid=" + kid + ", publicKey=" + publicKey + ", privateKey=<redacted>]";
		}

	}

	String kty();

	Optional<String> alg();

	Optional<String> kid();

	PublicKey publicKey();

	/// Parses a JWK from JSON text.
	///
	/// @param json The JWK as JSON text
	/// @return The parsed JWK, a [Private] if private key material is present
	/// @throws JoseParseException if the JSON is malformed, the key type is unsupported, or the key material is invalid or inconsistent
	static JWK parse(String json) throws JoseParseException {
		return parse(JsonHelper.parseObject(json));
	}

	/// Parses a JWK that must carry private key material, e.g. for decryption.
	///
	/// @param json The JWK as JSON text
	/// @return The parsed private JWK (which also carries the public key)
	/// @throws JoseParseException if the JWK is invalid or contains no private key material
	static Private parsePrivate(String json) throws JoseParseException {
		return parsePrivate(JsonHelper.parseObject(json));
	}

	/// Parses a JWK that must carry private key material, e.g. for decryption.
	///
	/// @param json The JWK as JSON object
	/// @return The parsed private JWK (which also carries the public key)
	/// @throws JoseParseException if the JWK is invalid or contains no private key material
	static Private parsePrivate(JsonObject json) throws JoseParseException {
		return switch (parse(json)) {
			case Private p -> p;
			case Public _ -> throw new JoseParseException("JWK contains no private key material");
		};
	}

	/// Parses the public part of a JWK, e.g. for encryption. Private key material, if present, is parsed and validated but not returned.
	///
	/// @param json The JWK as JSON text
	/// @return The parsed public JWK
	/// @throws JoseParseException if the JWK is invalid
	static Public parsePublic(String json) throws JoseParseException {
		return parsePublic(JsonHelper.parseObject(json));
	}

	/// Parses the public part of a JWK, e.g. for encryption. Private key material, if present, is parsed and validated but not returned.
	///
	/// @param json The JWK as JSON object
	/// @return The parsed public JWK
	/// @throws JoseParseException if the JWK is invalid
	static Public parsePublic(JsonObject json) throws JoseParseException {
		return switch (parse(json)) {
			case Private p -> p.toPublic();
			case Public p -> p;
		};
	}

	/// Parses a JWK from a JSON object.
	///
	/// @param json The JWK as JSON object
	/// @return The parsed JWK, a [Private] if private key material is present
	/// @throws JoseParseException if the key type is unsupported, or the key material is invalid or inconsistent
	static JWK parse(JsonObject json) throws JoseParseException {
		if (json == null) {
			throw new JoseParseException("JWK JSON must be an object");
		}
		String kty = JsonHelper.requireString(json, "kty");
		// see https://www.iana.org/assignments/jose/jose.xhtml#web-key-types
		var keyPair = switch (kty) {
			case "EC" -> ECHelper.fromJwk(json);
			case "AKP" -> akpFromJwk(json);
			// TODO: add further key types as needed
			default -> throw new JoseParseException("Unsupported JWK key type: " + kty);
		};
		var alg = optionalString(json, "alg");
		var kid = optionalString(json, "kid");
		return keyPair.getPrivate() == null
				? new Public(kty, alg, kid, keyPair.getPublic())
				: new Private(kty, alg, kid, keyPair.getPublic(), keyPair.getPrivate());
	}

	private static Optional<String> optionalString(JsonObject json, String key) throws JoseParseException {
		return json.has(key) ? Optional.of(JsonHelper.requireString(json, key)) : Optional.empty();
	}

	/// Parses an Algorithm Key Pair JWK as defined in [RFC 9964, Section 3](https://www.rfc-editor.org/rfc/rfc9964#section-3): `alg` and `pub` are required,
	/// `priv` is optional. For X-Wing, `pub` is the raw 1216-byte public key and `priv` the 32-byte seed. When both are present, the public key is re-derived from
	/// the seed and must match `pub`, since mismatched parameters may be tampering ([RFC 9964, Section 7.4](https://www.rfc-editor.org/rfc/rfc9964#section-7.4)).
	///
	/// @return The key pair, whose private key is `null` for a public JWK
	private static KeyPair akpFromJwk(JsonObject json) throws JoseParseException {
		var alg = JsonHelper.requireString(json, "alg");
		if (!alg.equals("HPKE-9") && !alg.equals("HPKE-9-KE")) { // both "HPKE-9" and "HPKE-9-KE" use the MLKEM768-X25519 (X-Wing) KEM
			throw new JoseParseException("Unsupported AKP algorithm: " + alg);
		}
		try {
			var kf = KeyFactory.getInstance("X-Wing", XwingProvider.INSTANCE);
			var publicKey = kf.generatePublic(rawKeySpec(JsonHelper.requireString(json, "pub")));
			if (!json.has("priv")) {
				return new KeyPair(publicKey, null);
			}
			var seed = Base64Url.decode(JsonHelper.requireString(json, "priv"));
			try {
				var seedSpec = new XwingSeedParameterSpec(seed);
				try {
					var keyGen = KeyPairGenerator.getInstance("X-Wing", XwingProvider.INSTANCE);
					keyGen.initialize(seedSpec);
					var derived = keyGen.generateKeyPair();
					if (!MessageDigest.isEqual(derived.getPublic().getEncoded(), publicKey.getEncoded())) {
						throw new JoseParseException("AKP 'pub' does not match the public key derived from 'priv'");
					}
					return derived;
				} finally {
					seedSpec.destroy();
				}
			} finally {
				Arrays.fill(seed, (byte) 0);
			}
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new AssertionError("Custom X-Wing provider must support X-Wing key factory and seeded key pair generation", e);
		} catch (IllegalArgumentException | InvalidKeySpecException e) {
			throw new JoseParseException("Invalid AKP key material", e);
		}
	}

	private static EncodedKeySpec rawKeySpec(String base64url) {
		return new EncodedKeySpec(Base64Url.decode(base64url)) {
			@Override
			public String getFormat() {
				return "RAW";
			}
		};
	}

}
