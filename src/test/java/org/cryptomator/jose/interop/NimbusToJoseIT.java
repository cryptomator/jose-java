package org.cryptomator.jose.interop;

import com.google.gson.JsonObject;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWEObjectJSON;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.MultiEncrypter;
import com.nimbusds.jose.crypto.PasswordBasedEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import org.cryptomator.jose.Alg;
import org.cryptomator.jose.DecryptionAlg;
import org.cryptomator.jose.JWE;
import org.cryptomator.jose.JoseException;
import org.cryptomator.jose.util.Curve;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/// Cross-implementation tests: nimbus-jose-jwt encrypts, jose-java decrypts.
///
/// nimbus 10.10 has two JSON-serialization code paths with different quirks, both exercised here:
/// - `JWEObjectJSON` with a single `JWEEncrypter` keeps `alg` in the protected header and moves alg-generated params (`epk`, `p2s`, `p2c`) into the
///   shared `unprotected` header. Without an explicit JWE AAD it binds the ciphertext to a header it does not serialize, so it is only usable with AAD.
/// - `MultiEncrypter` (two or more recipients) emits per-recipient `header` objects with `alg`, `kid` and the alg-generated params; `alg` must then be
///   absent from the protected header.
@DisplayName("nimbus → jose-java")
class NimbusToJoseIT {

	enum Serialization {COMPACT, FLATTENED, GENERAL}

	/// A key management algorithm as seen by both libraries.
	record KeyAlg(String name, JWEAlgorithm nimbusAlg, JWEEncrypter nimbusEncrypter, DecryptionAlg joseAlg) {

		static KeyAlg ecdhEs(Curve curve) throws JoseException, JOSEException {
			var name = "ECDH-ES+A256KW/" + curve.name();
			var encrypter = new ECDHEncrypter(InteropFixtures.nimbusEcKey(curve).toECPublicKey());
			return new KeyAlg(name, JWEAlgorithm.ECDH_ES_A256KW, encrypter, joseEcdhEs(curve));
		}

		static KeyAlg pbes2() {
			var encrypter = new PasswordBasedEncrypter(new String(InteropFixtures.PASSWORD), 16, InteropFixtures.PBES2_ITERATIONS);
			return new KeyAlg("PBES2-HS512+A256KW", JWEAlgorithm.PBES2_HS512_A256KW, encrypter, Alg.pbes2(InteropFixtures.PASSWORD));
		}

		static KeyAlg a256kw() throws JOSEException {
			var encrypter = new AESEncrypter(InteropFixtures.joseKek());
			return new KeyAlg("A256KW", JWEAlgorithm.A256KW, encrypter, Alg.a256kw(InteropFixtures.joseKek()));
		}

		static List<KeyAlg> all() throws JoseException, JOSEException {
			return List.of(ecdhEs(Curve.P256), ecdhEs(Curve.P384), ecdhEs(Curve.P521), pbes2(), a256kw());
		}

	}

	record ContentEnc(String name, EncryptionMethod nimbusEnc) {

		static List<ContentEnc> all() {
			return List.of(new ContentEnc("A128GCM", EncryptionMethod.A128GCM), new ContentEnc("A256GCM", EncryptionMethod.A256GCM));
		}

	}

	static DecryptionAlg joseEcdhEs(Curve curve) throws JoseException {
		return Alg.ecdhEs(InteropFixtures.josePrivateKey(curve));
	}

	static void addProtectedExtras(JWEHeader.Builder header, JsonObject protectedExtras) {
		for (var extra : protectedExtras.entrySet()) {
			switch (extra.getKey()) { // nimbus refuses registered names as custom params
				case "typ" -> header.type(new JOSEObjectType(extra.getValue().getAsString()));
				case "cty" -> header.contentType(extra.getValue().getAsString());
				default -> header.customParam(extra.getKey(), NimbusJson.toJavaObject(extra.getValue()));
			}
		}
	}

	/// Encrypts for a single recipient with nimbus, returning the requested serialization.
	static String nimbusEncrypt(KeyAlg alg, ContentEnc enc, Serialization serialization, String payload, JsonObject protectedExtras, String aad) throws JOSEException {
		var header = new JWEHeader.Builder(alg.nimbusAlg(), enc.nimbusEnc());
		addProtectedExtras(header, protectedExtras);
		switch (serialization) {
			case COMPACT -> {
				Assertions.assertTrue(aad.isEmpty(), "compact serialization cannot carry AAD");
				var jwe = new JWEObject(header.build(), new Payload(payload));
				jwe.encrypt(alg.nimbusEncrypter());
				return jwe.serialize();
			}
			case FLATTENED, GENERAL -> {
				Assertions.assertFalse(aad.isEmpty(), "nimbus' single-recipient JSON serialization is only sound with an explicit AAD");
				var aadBytes = aad.getBytes(StandardCharsets.US_ASCII); // nimbus expects the base64url text as ASCII bytes
				var jwe = new JWEObjectJSON(header.build(), new Payload(payload), null, aadBytes);
				jwe.encrypt(alg.nimbusEncrypter());
				return serialization == Serialization.FLATTENED ? jwe.serializeFlattened() : jwe.serializeGeneral();
			}
		}
		throw new AssertionError();
	}

	/// Encrypts for two ECDH-ES recipients with nimbus' `MultiEncrypter`, returning the general JSON serialization.
	static String nimbusEncryptMulti(List<Curve> recipients, ContentEnc enc, String payload, JsonObject protectedExtras, String aad) throws JOSEException {
		var header = new JWEHeader.Builder(enc.nimbusEnc()); // alg is per recipient
		addProtectedExtras(header, protectedExtras);
		var keys = recipients.stream().map(curve -> (com.nimbusds.jose.jwk.JWK) new ECKey.Builder(InteropFixtures.nimbusEcKey(curve)).algorithm(JWEAlgorithm.ECDH_ES_A256KW).build()).toList();
		var aadBytes = aad.isEmpty() ? null : aad.getBytes(StandardCharsets.US_ASCII);
		var jwe = new JWEObjectJSON(header.build(), new Payload(payload), null, aadBytes);
		jwe.encrypt(new MultiEncrypter(new JWKSet(keys)));
		return jwe.serializeGeneral();
	}

	@ParameterizedTest
	@MethodSource
	@DisplayName("compact: alg × enc")
	void compact(KeyAlg alg, ContentEnc enc) throws JOSEException, JoseException {
		var payload = InteropFixtures.PAYLOADS.get("ascii");
		var jwe = nimbusEncrypt(alg, enc, Serialization.COMPACT, payload, new JsonObject(), "");

		var decrypted = JWE.parse(jwe).decrypt(alg.joseAlg());

		Assertions.assertEquals(payload, decrypted.payload());
		Assertions.assertEquals(enc.name(), decrypted.protectedHeader().get("enc").getAsString());
		Assertions.assertEquals(alg.nimbusAlg().getName(), decrypted.protectedHeader().get("alg").getAsString());
		Assertions.assertEquals("", decrypted.aad());
	}

	static Stream<Arguments> compact() throws JoseException, JOSEException {
		var result = Stream.<Arguments>builder();
		for (var alg : KeyAlg.all()) {
			for (var enc : ContentEnc.all()) {
				result.add(Arguments.argumentSet(alg.name() + " " + enc.name(), alg, enc));
			}
		}
		return result.build();
	}

	@ParameterizedTest
	@MethodSource
	@DisplayName("compact: payload × protected header")
	void compactPayloadHeader(String payloadName, String extrasName) throws JOSEException, JoseException {
		var alg = KeyAlg.ecdhEs(Curve.P384);
		var enc = ContentEnc.all().getLast();
		var payload = InteropFixtures.PAYLOADS.get(payloadName);
		var extras = InteropFixtures.PROTECTED_HEADER_EXTRAS.get(extrasName);
		var jwe = nimbusEncrypt(alg, enc, Serialization.COMPACT, payload, extras, "");

		var decrypted = JWE.parse(jwe).decrypt(alg.joseAlg());

		Assertions.assertEquals(payload, decrypted.payload());
		for (var extra : extras.entrySet()) {
			Assertions.assertEquals(extra.getValue(), decrypted.protectedHeader().get(extra.getKey()), "protected header param " + extra.getKey());
		}
	}

	static Stream<Arguments> compactPayloadHeader() {
		var result = Stream.<Arguments>builder();
		for (var payload : InteropFixtures.PAYLOADS.keySet().stream().sorted().toList()) {
			for (var extras : InteropFixtures.PROTECTED_HEADER_EXTRAS.keySet().stream().sorted().toList()) {
				result.add(Arguments.argumentSet(payload + " " + extras, payload, extras));
			}
		}
		return result.build();
	}

	@ParameterizedTest
	@MethodSource
	@DisplayName("single-recipient JSON with AAD: alg × serialization (alg params in the shared unprotected header)")
	void singleRecipientJsonWithAad(KeyAlg alg, Serialization serialization) throws JOSEException, JoseException {
		var enc = ContentEnc.all().getLast();
		var payload = InteropFixtures.PAYLOADS.get("utf8");
		var jwe = nimbusEncrypt(alg, enc, serialization, payload, new JsonObject(), InteropFixtures.AAD);

		var decrypted = JWE.parse(jwe).decrypt(alg.joseAlg());

		Assertions.assertEquals(payload, decrypted.payload());
		Assertions.assertEquals(InteropFixtures.AAD, decrypted.aad());
		Assertions.assertEquals(alg.nimbusAlg().getName(), decrypted.protectedHeader().get("alg").getAsString());
		if (!JWEAlgorithm.A256KW.equals(alg.nimbusAlg())) { // A256KW is the only alg here that generates no header params
			Assertions.assertFalse(decrypted.unprotectedHeader().isEmpty(), "alg-generated params are expected in the shared unprotected header");
		}
	}

	static Stream<Arguments> singleRecipientJsonWithAad() throws JoseException, JOSEException {
		var result = Stream.<Arguments>builder();
		for (var alg : KeyAlg.all()) {
			for (var serialization : List.of(Serialization.FLATTENED, Serialization.GENERAL)) {
				result.add(Arguments.argumentSet(alg.name() + " " + serialization, alg, serialization));
			}
		}
		return result.build();
	}

	@ParameterizedTest
	@MethodSource
	@DisplayName("general JSON, two ECDH-ES recipients: curves × enc × AAD × protected header")
	void twoRecipients(List<Curve> recipients, ContentEnc enc, String aad, String extrasName) throws JOSEException, JoseException {
		var payload = InteropFixtures.PAYLOADS.get("long");
		var extras = InteropFixtures.PROTECTED_HEADER_EXTRAS.get(extrasName);
		var jwe = nimbusEncryptMulti(recipients, enc, payload, extras, aad);

		for (var curve : recipients) {
			var decrypted = JWE.parse(jwe).decrypt(joseEcdhEs(curve));

			Assertions.assertEquals(payload, decrypted.payload(), "recipient " + curve);
			Assertions.assertEquals(aad, decrypted.aad());
			Assertions.assertFalse(decrypted.protectedHeader().has("alg"));
			Assertions.assertEquals("ECDH-ES+A256KW", decrypted.unprotectedHeader().get("alg").getAsString());
			Assertions.assertEquals(InteropFixtures.nimbusEcKey(curve).getKeyID(), decrypted.unprotectedHeader().get("kid").getAsString());
			Assertions.assertEquals(curve.jwaCrvName, decrypted.unprotectedHeader().getAsJsonObject("epk").get("crv").getAsString());
			for (var extra : extras.entrySet()) {
				Assertions.assertEquals(extra.getValue(), decrypted.protectedHeader().get(extra.getKey()), "protected header param " + extra.getKey());
			}
		}
	}

	static Stream<Arguments> twoRecipients() {
		var result = Stream.<Arguments>builder();
		var curvePairs = List.of(List.of(Curve.P256, Curve.P384), List.of(Curve.P384, Curve.P521), List.of(Curve.P521, Curve.P256));
		for (var pair : curvePairs) {
			for (var enc : ContentEnc.all()) {
				for (var aad : List.of("", InteropFixtures.AAD)) {
					for (var extras : List.of("none", "private-int")) {
						var label = pair.getFirst() + "+" + pair.getLast() + " " + enc.name() + (aad.isEmpty() ? "" : " aad") + " " + extras;
						result.add(Arguments.argumentSet(label, pair, enc, aad, extras));
					}
				}
			}
		}
		return result.build();
	}

	/// Converts Gson values to the plain Java objects nimbus uses for custom header params.
	static final class NimbusJson {

		static Object toJavaObject(com.google.gson.JsonElement element) {
			if (element.isJsonNull()) {
				return null;
			} else if (element.isJsonPrimitive()) {
				var primitive = element.getAsJsonPrimitive();
				if (primitive.isBoolean()) {
					return primitive.getAsBoolean();
				} else if (primitive.isNumber()) {
					return primitive.getAsNumber().longValue();
				} else {
					return primitive.getAsString();
				}
			} else if (element.isJsonArray()) {
				return element.getAsJsonArray().asList().stream().map(NimbusJson::toJavaObject).toList();
			} else {
				var map = new java.util.LinkedHashMap<String, Object>();
				element.getAsJsonObject().entrySet().forEach(e -> map.put(e.getKey(), toJavaObject(e.getValue())));
				return Map.copyOf(map);
			}
		}

	}

}
