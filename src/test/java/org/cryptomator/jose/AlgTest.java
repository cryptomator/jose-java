package org.cryptomator.jose;

import org.cryptomator.jose.util.Base64Url;
import org.cryptomator.jose.util.Curve;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.function.Function;
import java.util.stream.Stream;

class AlgTest {

	// an EC private JWK for the curve, with or without an alg parameter
	private static String ecJwk(Curve curve, String alg) {
		var keyPair = curve.generateKeyPair();
		var pub = (ECPublicKey) keyPair.getPublic();
		var priv = (ECPrivateKey) keyPair.getPrivate();
		return "{\"kty\":\"EC\",\"crv\":\"" + curve.jwaCrvName + "\""
				+ (alg == null ? "" : ",\"alg\":\"" + alg + "\"")
				+ ",\"x\":\"" + fixedLength(pub.getW().getAffineX(), curve) + "\""
				+ ",\"y\":\"" + fixedLength(pub.getW().getAffineY(), curve) + "\""
				+ ",\"d\":\"" + fixedLength(priv.getS(), curve) + "\"}";
	}

	private static String fixedLength(BigInteger value, Curve curve) {
		var bytes = value.toByteArray();
		var result = new byte[curve.coordinateByteLength];
		var src = bytes.length > result.length ? bytes.length - result.length : 0; // strip a leading sign byte
		System.arraycopy(bytes, src, result, result.length - (bytes.length - src), bytes.length - src);
		return Base64Url.encode(result);
	}

	static Stream<Arguments> ecFactories() {
		return Stream.of(
				Arguments.of("ECDH-ES+A256KW", Curve.P256, (Function<JWK.Public, Alg>) Alg::ecdhEs, (Function<JWK.Private, Alg>) Alg::ecdhEs),
				Arguments.of("HPKE-0", Curve.P256, (Function<JWK.Public, Alg>) Alg::hpke0, (Function<JWK.Private, Alg>) Alg::hpke0),
				Arguments.of("HPKE-1", Curve.P384, (Function<JWK.Public, Alg>) Alg::hpke1, (Function<JWK.Private, Alg>) Alg::hpke1),
				Arguments.of("HPKE-2", Curve.P521, (Function<JWK.Public, Alg>) Alg::hpke2, (Function<JWK.Private, Alg>) Alg::hpke2),
				Arguments.of("HPKE-0-KE", Curve.P256, (Function<JWK.Public, Alg>) Alg::hpke0Ke, (Function<JWK.Private, Alg>) Alg::hpke0Ke),
				Arguments.of("HPKE-1-KE", Curve.P384, (Function<JWK.Public, Alg>) Alg::hpke1Ke, (Function<JWK.Private, Alg>) Alg::hpke1Ke),
				Arguments.of("HPKE-2-KE", Curve.P521, (Function<JWK.Public, Alg>) Alg::hpke2Ke, (Function<JWK.Private, Alg>) Alg::hpke2Ke)
		);
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("ecFactories")
	@DisplayName("JWK factories accept an absent or matching alg and reject a foreign one")
	void testEcJwkAlgBinding(String alg, Curve curve, Function<JWK.Public, Alg> publicFactory, Function<JWK.Private, Alg> privateFactory) throws JoseParseException {
		var withoutAlg = JWK.parsePrivate(ecJwk(curve, null));
		var matching = JWK.parsePrivate(ecJwk(curve, alg));
		var foreign = JWK.parsePrivate(ecJwk(curve, alg.equals("HPKE-0") ? "ECDH-ES+A256KW" : "HPKE-0")); // same curve, other algorithm

		Assertions.assertEquals(alg, publicFactory.apply(withoutAlg.toPublic()).name());
		Assertions.assertEquals(alg, privateFactory.apply(withoutAlg).name());
		Assertions.assertEquals(alg, publicFactory.apply(matching.toPublic()).name());
		Assertions.assertEquals(alg, privateFactory.apply(matching).name());
		Assertions.assertThrows(IllegalArgumentException.class, () -> publicFactory.apply(foreign.toPublic()));
		Assertions.assertThrows(IllegalArgumentException.class, () -> privateFactory.apply(foreign));
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("ecFactories")
	@DisplayName("forJwk picks the decryption algorithm named by the JWK's alg")
	void testForJwk(String alg, Curve curve, Function<JWK.Public, Alg> publicFactory, Function<JWK.Private, Alg> privateFactory) throws JoseParseException {
		Assertions.assertEquals(alg, Alg.forJwk(JWK.parsePrivate(ecJwk(curve, alg))).name());
	}

	@Test
	@DisplayName("forJwk requires an alg and rejects unknown ones")
	void testForJwkRequiresKnownAlg() throws JoseParseException {
		Assertions.assertThrows(IllegalArgumentException.class, () -> Alg.forJwk(JWK.parsePrivate(ecJwk(Curve.P256, null))));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Alg.forJwk(JWK.parsePrivate(ecJwk(Curve.P256, "ES256"))));
	}

	@Test
	@DisplayName("forJwk round-trips a JWE end to end")
	void testForJwkRoundTrip() throws JoseException {
		var jwk = JWK.parsePrivate(ecJwk(Curve.P384, "HPKE-1-KE"));
		var token = JWE.build("payload").encrypt(Enc.A256GCM, Alg.hpke1Ke(jwk.toPublic())).toCompactSerialization();
		Assertions.assertEquals("payload", JWE.parse(token).decrypt(Alg.forJwk(jwk)).payload());
	}

}
