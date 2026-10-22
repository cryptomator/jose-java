package org.cryptomator.jose.interop;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWEObjectJSON;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.PasswordBasedDecrypter;
import org.cryptomator.jose.Alg;
import org.cryptomator.jose.Enc;
import org.cryptomator.jose.JWE;
import org.cryptomator.jose.JoseException;
import org.cryptomator.jose.KeyEncryptionAlg;
import org.cryptomator.jose.util.Curve;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.text.ParseException;
import java.util.List;
import java.util.stream.Stream;

/// Cross-implementation tests: jose-java encrypts, nimbus-jose-jwt decrypts.
@DisplayName("jose-java → nimbus")
class JoseToNimbusIT {

	enum Serialization {COMPACT, FLATTENED, GENERAL}

	/// A key management algorithm as seen by both libraries.
	record KeyAlg(String name, KeyEncryptionAlg joseAlg, JWEDecrypter nimbusDecrypter) {

		static KeyAlg ecdhEs(Curve curve) throws JoseException, JOSEException {
			var name = "ECDH-ES+A256KW/" + curve.name();
			var joseAlg = Alg.ecdhEs(InteropFixtures.josePublicKey(curve));
			var decrypter = new ECDHDecrypter(InteropFixtures.nimbusEcKey(curve).toECPrivateKey());
			return new KeyAlg(name, joseAlg, decrypter);
		}

		static KeyAlg pbes2() {
			var joseAlg = Alg.pbes2(InteropFixtures.PASSWORD, InteropFixtures.PBES2_ITERATIONS);
			return new KeyAlg("PBES2-HS512+A256KW", joseAlg, new PasswordBasedDecrypter(new String(InteropFixtures.PASSWORD)));
		}

		static KeyAlg a256kw() throws JOSEException {
			return new KeyAlg("A256KW", Alg.a256kw(InteropFixtures.joseKek()), new AESDecrypter(InteropFixtures.joseKek()));
		}

		static List<KeyAlg> all() throws JoseException, JOSEException {
			return List.of(ecdhEs(Curve.P256), ecdhEs(Curve.P384), ecdhEs(Curve.P521), pbes2(), a256kw());
		}

	}

	/// Encrypts with jose-java (single recipient, no AAD, so all three serializations are available), returning the requested serialization.
	static String joseEncrypt(KeyAlg alg, Enc enc, Serialization serialization, String payload, JsonObject protectedExtras) {
		var encrypted = JWE.build(payload).withProtectedHeader(protectedExtras).encrypt(enc, alg.joseAlg());
		return switch (serialization) {
			case COMPACT -> encrypted.toCompactSerialization();
			case FLATTENED -> encrypted.toFlattenedJsonSerialization();
			case GENERAL -> encrypted.toJsonSerialization();
		};
	}

	/// Decrypts with nimbus, returning the payload and the (protected) header as seen by nimbus.
	record NimbusResult(String payload, JsonObject header) {
	}

	static NimbusResult nimbusDecrypt(String jwe, Serialization serialization, JWEDecrypter decrypter) throws ParseException, JOSEException {
		if (serialization == Serialization.COMPACT) {
			var parsed = JWEObject.parse(jwe);
			parsed.decrypt(decrypter);
			return new NimbusResult(parsed.getPayload().toString(), JsonParser.parseString(parsed.getHeader().toString()).getAsJsonObject());
		} else {
			var parsed = JWEObjectJSON.parse(jwe);
			parsed.decrypt(decrypter);
			return new NimbusResult(parsed.getPayload().toString(), JsonParser.parseString(parsed.getHeader().toString()).getAsJsonObject());
		}
	}

	@ParameterizedTest
	@MethodSource
	@DisplayName("alg × enc × serialization")
	void algEncSerialization(KeyAlg alg, Enc enc, Serialization serialization) throws JOSEException, ParseException {
		var payload = InteropFixtures.PAYLOADS.get("ascii");
		var jwe = joseEncrypt(alg, enc, serialization, payload, new JsonObject());

		var result = nimbusDecrypt(jwe, serialization, alg.nimbusDecrypter());

		Assertions.assertEquals(payload, result.payload());
		Assertions.assertEquals(enc.encValue(), result.header().get("enc").getAsString());
		Assertions.assertEquals(alg.joseAlg().name(), result.header().get("alg").getAsString());
	}

	static Stream<Arguments> algEncSerialization() throws JoseException, JOSEException {
		var result = Stream.<Arguments>builder();
		for (var alg : KeyAlg.all()) {
			for (var enc : List.of(Enc.A128GCM, Enc.A256GCM)) {
				for (var serialization : Serialization.values()) {
					result.add(Arguments.argumentSet(alg.name() + " " + enc.encValue() + " " + serialization, alg, enc, serialization));
				}
			}
		}
		return result.build();
	}

	@ParameterizedTest
	@MethodSource
	@DisplayName("payload × protected header × serialization")
	void payloadHeaderSerialization(String payloadName, String extrasName, Serialization serialization) throws JOSEException, JoseException, ParseException {
		var alg = KeyAlg.ecdhEs(Curve.P384);
		var payload = InteropFixtures.PAYLOADS.get(payloadName);
		var extras = InteropFixtures.PROTECTED_HEADER_EXTRAS.get(extrasName);
		var jwe = joseEncrypt(alg, Enc.A256GCM, serialization, payload, extras);

		var result = nimbusDecrypt(jwe, serialization, alg.nimbusDecrypter());

		Assertions.assertEquals(payload, result.payload());
		for (var extra : extras.entrySet()) {
			Assertions.assertEquals(extra.getValue(), result.header().get(extra.getKey()), "protected header param " + extra.getKey());
		}
	}

	static Stream<Arguments> payloadHeaderSerialization() {
		var result = Stream.<Arguments>builder();
		for (var payload : InteropFixtures.PAYLOADS.keySet().stream().sorted().toList()) {
			for (var extras : InteropFixtures.PROTECTED_HEADER_EXTRAS.keySet().stream().sorted().toList()) {
				for (var serialization : Serialization.values()) {
					result.add(Arguments.argumentSet(payload + " " + extras + " " + serialization, payload, extras, serialization));
				}
			}
		}
		return result.build();
	}

}
