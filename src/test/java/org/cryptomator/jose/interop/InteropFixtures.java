package org.cryptomator.jose.interop;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.cryptomator.jose.JWK;
import org.cryptomator.jose.JoseParseException;
import org.cryptomator.jose.util.Curve;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.Map;

/// Fixed (deterministic) inputs shared by the cross-implementation tests: keys, payloads, and header variations.
/// Only the inputs are fixed; ciphertexts differ per run because the CEK, IV and ephemeral keys are random in both libraries,
/// which is why every case is verified by decrypting with the other implementation.
final class InteropFixtures {

	private InteropFixtures() {
	}

	// EC private JWKs taken from draft-ietf-jose-hpke-encrypt-22, Appendix A.1 / A.3 / A.5 (HPKE-specific alg/use members removed)
	static final String P256_JWK = """
			{
			  "kty": "EC",
			  "crv": "P-256",
			  "x": "qy-BxXhaelX9Fqe8muRTu8HhseHYgMMGxyfAnIy0MC0",
			  "y": "ctfHN7Y4pkj7vZI-sgJ6BqsYwG-PDnB8j7TsfzHHJOI",
			  "d": "aAKxBMAkNm2AZDGv7LN5yodDwahJ5rKbrgiiz3dUIH4",
			  "kid": "KfvD-eYaynUKba0ow-v9uoEV-twV6mYDyiAOWO6LoPM"
			}
			""";
	static final String P384_JWK = """
			{
			  "kty": "EC",
			  "crv": "P-384",
			  "x": "CTphb4EF35SSZgrk9rYHXkdalQLTGRApFRiAF8eVteQtOIZRbZKV0iEv9eiSElLT",
			  "y": "6KddFD8aAVzoJNq1Jr_4oZ3t7SGZm3qgXMHN7sB_KAlxTydxRaVXArFKQyyffOj6",
			  "d": "UzFpz5G-_kWkiCKWCWdRXFxVoz9fTY4u9I_XmfPoOI7eEf0glEARLbsx06wb1EYu",
			  "kid": "K4P-SJHnqUpz-qTXlYCBV6ITFu8sH_gsx2KGMEcjk9s"
			}
			""";
	static final String P521_JWK = """
			{
			  "kty": "EC",
			  "crv": "P-521",
			  "x": "ACDaefJAD-xbCAk4C5QadlEtEinEV9JRqyz7MHzSjK-8V2zn0dvNYRtdQYfyddZ1LiN9dzTxuyEaqlJ44-NzoJQc",
			  "y": "AF9ye0Rd9NTTGSTlkBUcpzXttxHOaTfQi5E6QNublPXTyuRX-X54EDzdy1tnsBECHNmTAx7rNiR42_Y6ZbKauCTE",
			  "d": "APRq4c1AiF5IoYKHKz7TaFknSvSxn-gH5ZurH386OD1dO6I2tcbHlfPPoFUO8miVUihJuHIpcxDFGIRwe6kgPZ-V",
			  "kid": "MDVVyxq8x1VX7I1X3oVf3nJY51r55uNlZ9xHpC-7sS0"
			}
			""";

	static final Map<Curve, String> EC_JWKS = Map.of(Curve.P256, P256_JWK, Curve.P384, P384_JWK, Curve.P521, P521_JWK);

	// 256-bit key encryption key: 0x00, 0x01, ..., 0x1f
	static final byte[] KEK_BYTES = new byte[32];

	static {
		for (int i = 0; i < KEK_BYTES.length; i++) {
			KEK_BYTES[i] = (byte) i;
		}
	}

	static final char[] PASSWORD = "correct horse battery staple".toCharArray();
	static final int PBES2_ITERATIONS = 1000; // nimbus refuses to encrypt with fewer than 1000 iterations

	static final String AAD = Base64.getUrlEncoder().withoutPadding().encodeToString("The Fellowship of the Ring".getBytes());

	/// Payload variations: ASCII, non-ASCII (an en-dash and umlauts), empty, and one spanning several AES blocks.
	static final Map<String, String> PAYLOADS = Map.of(
			"ascii", "You can trust us to stick with you through thick and thin.",
			"utf8", "Größe – Übermaß – naïve",
			"empty", "",
			"long", "0123456789abcdef".repeat(256)
	);

	/// Protected header variations beyond `alg`/`enc`: none, a registered string param, a private param of each JSON type.
	static final Map<String, JsonObject> PROTECTED_HEADER_EXTRAS = Map.of(
			"none", json("{}"),
			"cty", json("{\"cty\":\"json\"}"),
			"typ", json("{\"typ\":\"JOSE\"}"),
			"private-int", json("{\"org.example.version\":1}"),
			"private-string", json("{\"org.example.label\":\"vault\"}"),
			"private-array", json("{\"org.example.tags\":[\"a\",\"b\"]}"),
			"private-object", json("{\"org.example.meta\":{\"k\":\"v\",\"n\":2}}")
	);

	static JsonObject json(String json) {
		return JsonParser.parseString(json).getAsJsonObject();
	}

	// jose-java keys:

	static ECPrivateKey josePrivateKey(Curve curve) throws JoseParseException {
		return (ECPrivateKey) JWK.parse(EC_JWKS.get(curve));
	}

	static ECPublicKey josePublicKey(Curve curve) throws JoseParseException {
		var jwk = json(EC_JWKS.get(curve));
		jwk.remove("d"); // JWK.parse returns the public key iff "d" is absent
		return (ECPublicKey) JWK.parse(jwk);
	}

	static SecretKey joseKek() {
		return new SecretKeySpec(KEK_BYTES, "AES");
	}

	// nimbus keys:

	static ECKey nimbusEcKey(Curve curve) {
		try {
			return ECKey.parse(EC_JWKS.get(curve));
		} catch (ParseException e) {
			throw new IllegalStateException("Fixture JWK must parse", e);
		}
	}

	static OctetSequenceKey nimbusKek() {
		return new OctetSequenceKey.Builder(KEK_BYTES).build();
	}

}
