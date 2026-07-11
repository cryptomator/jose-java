package org.cryptomator.jose;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;

class JWKTest {

	@Nested
	@DisplayName("AKP JWK")
	class Akp {

		// the "priv" value (X-Wing seed) of the AKP JWK from draft-ietf-jose-hpke-pq-pqt-01 Appendix A.4
		private static final String PRIV = "q_aDEMZpRAjbiqHwO23vKcgImYieSqUsCK7wWZEsq8Y";

		@Test
		@DisplayName("a valid AKP private JWK parses")
		void testValid() throws JoseParseException {
			var key = JWK.parse("{\"kty\":\"AKP\",\"alg\":\"HPKE-9-KE\",\"priv\":\"" + PRIV + "\"}");
			Assertions.assertInstanceOf(PrivateKey.class, key);
		}

		@Test
		@DisplayName("a non-string alg is rejected")
		void testNonStringAlg() {
			Assertions.assertThrows(JoseParseException.class, () -> JWK.parse("{\"kty\":\"AKP\",\"alg\":{},\"priv\":\"" + PRIV + "\"}"));
		}

		@Test
		@DisplayName("a non-string priv is rejected")
		void testNonStringPriv() {
			Assertions.assertThrows(JoseParseException.class, () -> JWK.parse("{\"kty\":\"AKP\",\"alg\":\"HPKE-9-KE\",\"priv\":{}}"));
		}

		@Test
		@DisplayName("an alg that merely starts with HPKE-9 is rejected")
		void testAlgPrefixNotAccepted() {
			var thrown = Assertions.assertThrows(JoseParseException.class, () -> JWK.parse("{\"kty\":\"AKP\",\"alg\":\"HPKE-90\",\"priv\":\"" + PRIV + "\"}"));
			Assertions.assertTrue(thrown.getMessage().contains("Unsupported AKP algorithm"));
		}
	}

	@Test
	@DisplayName("a non-string kty is rejected")
	void testNonStringKty() {
		Assertions.assertThrows(JoseParseException.class, () -> JWK.parse("{\"kty\":{}}"));
	}
}
