package org.cryptomator.jose.interop;

import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import org.cryptomator.jose.JWS;
import org.cryptomator.jose.JoseException;
import org.cryptomator.jose.JoseParseException;
import org.cryptomator.jose.MacAlg;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.text.ParseException;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

/// Cross-implementation tests for JWS: nimbus signs, jose-java verifies, and vice versa.
@DisplayName("JWS: nimbus ↔ jose-java")
class JwsInteropIT {

	private static final SecretKey KEY = new SecretKeySpec("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".getBytes(), "HmacSHA256"); // 64 bytes, enough for HS512

	record Hmac(String name, JWSAlgorithm nimbusAlg, Function<SecretKey, MacAlg> joseAlg) {
	}

	static List<Hmac> algs() {
		return List.of(new Hmac("HS256", JWSAlgorithm.HS256, MacAlg::hs256), new Hmac("HS384", JWSAlgorithm.HS384, MacAlg::hs384), new Hmac("HS512", JWSAlgorithm.HS512, MacAlg::hs512));
	}

	static Stream<Arguments> cases() {
		var result = Stream.<Arguments>builder();
		for (var alg : algs()) {
			for (var payload : InteropFixtures.PAYLOADS.keySet().stream().sorted().toList()) {
				result.add(Arguments.argumentSet(alg.name() + " " + payload, alg, InteropFixtures.PAYLOADS.get(payload)));
			}
		}
		return result.build();
	}

	@ParameterizedTest
	@MethodSource("cases")
	@DisplayName("nimbus → jose-java: typ, kid, crit")
	void nimbusToJose(Hmac alg, String payload) throws JOSEException, JoseException {
		var header = new JWSHeader.Builder(alg.nimbusAlg()).type(JOSEObjectType.JWT).keyID("masterkey").criticalParams(Set.of("org.example.v")).customParam("org.example.v", 1L).build();
		var jws = new JWSObject(header, new Payload(payload));
		jws.sign(new MACSigner(KEY));
		var token = jws.serialize();

		var verified = JWS.parse(token, "org.example.v").verify(alg.joseAlg().apply(KEY));
		Assertions.assertEquals(payload, verified.payload());
		Assertions.assertEquals("JWT", verified.protectedHeader().get("typ").getAsString());
		Assertions.assertEquals("masterkey", verified.protectedHeader().get("kid").getAsString());
		Assertions.assertEquals(1, verified.protectedHeader().get("org.example.v").getAsInt());
		Assertions.assertThrows(JoseParseException.class, () -> JWS.parse(token)); // crit not understood
	}

	@ParameterizedTest
	@MethodSource("cases")
	@DisplayName("jose-java → nimbus: typ, kid, crit")
	void joseToNimbus(Hmac alg, String payload) throws JOSEException, ParseException {
		var header = JsonParser.parseString("{\"typ\":\"JWT\",\"kid\":\"masterkey\",\"crit\":[\"org.example.v\"],\"org.example.v\":1}").getAsJsonObject();
		var token = JWS.build(payload).withProtectedHeader(header).sign(alg.joseAlg().apply(KEY));

		var jws = JWSObject.parse(token);
		Assertions.assertTrue(jws.verify(new MACVerifier(KEY, Set.of("org.example.v"))));
		Assertions.assertEquals(payload, jws.getPayload().toString());
		Assertions.assertEquals(alg.nimbusAlg(), jws.getHeader().getAlgorithm());
		Assertions.assertEquals(JOSEObjectType.JWT, jws.getHeader().getType());
		Assertions.assertEquals("masterkey", jws.getHeader().getKeyID());
		Assertions.assertFalse(jws.verify(new MACVerifier(KEY))); // nimbus reports an undeferred crit as a failed verification, not as an exception
	}

}
