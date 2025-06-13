package org.cryptomator.jose.alg;

import com.google.common.io.BaseEncoding;
import org.cryptomator.jose.JWE;
import org.cryptomator.jose.JWK;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.JoseParseException;
import org.cryptomator.jose.util.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.spec.SecretKeySpec;
import java.security.interfaces.ECPrivateKey;

class HPKEAlgTest {


	@Nested
	public class HPKEExamples {

		private ECPrivateKey privateKey;

		@BeforeEach
		public void setup() throws JoseParseException {
			// Example JWK from https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#appendix-A
			var jwk = """
					{
					  "kty": "EC",
					  "use": "enc",
					  "alg": "HPKE-0",
					  "kid": "G5N__CqMv_kJGieGSFuAugvl0jrQJCZ3yKwVK6sUM4o",
					  "crv": "P-256",
					  "x": "gixQJ0qg4Ag-6HSMaIEDL_zbDhoXavMyKlmdn__AQVE",
					  "y": "ZxTgRLWaKONCL_GbZKLNPsW9EW6nBsN4AwQGEFAFFbM",
					  "d": "g2DXtKapi2oN2zL_RCWX8D4bWURHCKN2-ZNGC05ZaR8"
					}
					""";
			this.privateKey = (ECPrivateKey) JWK.parse(jwk);
		}

		// test vectors from https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-5.2
		@Test
		@DisplayName("parse json serialization and decrypt with HPKE-0")
		public void decryptJsonJWE() throws JoseParseException, JoseDecryptException {
			var jwe = """
					{
					  "protected": "eyJlbmMiOiAiQTEyOEdDTSJ9",
					  "ciphertext": "9AxOd65ROJY1cQ",
					  "iv": "2u3NRi3CSr-x7Wuj",
					  "tag": "1NKYSWVV4pw5thsq7t6m6Q",
					  "recipients": [
					    {
					      "encrypted_key": "l9VRW1K5CA037fY2ZqVF4bDej413TaAtfjoe3k89-eI",
					      "header": {
					        "alg": "HPKE-0",
					        "kid": "G5N__CqMv_kJGieGSFuAugvl0jrQJCZ3yKwVK6sUM4o",
					        "ek": "BJl0V6KLl3HOAZbzFwiAL9eaYbFQPg7-ROmIJpluIQjNS5zultZsC4rGhGzmW1GUWG8bzJUWLQtxFF9oze0AKhU"
					      }
					    }
					  ]
					}
					""";
			var decrypted = JWE.parse(jwe).decrypt(new HPKE0Alg(null, privateKey));
			Assertions.assertEquals("hello \uD83C\uDF0E", decrypted.payload());
		}

	}


	// test vectors from https://www.rfc-editor.org/rfc/rfc9180#appendix-A.6.2.1
	@Nested
	@DisplayName("test HPKE key schedule")
	public class KeySchedule {

		private static HPKEAlg.Context context;

		@BeforeAll
		public static void setup() {
			var hpke = new HPKE2Alg(null, null); // DHKEM(P-521, HKDF-SHA512) + HKDF-SHA512 + AES-256-GCM
			var sharedSecret = new SecretKeySpec(BaseEncoding.base16().ignoreCase().decode("776ab421302f6eff7d7cb5cb1adaea0cd50872c71c2d63c30c4f1d5e43653336fef33b103c67e7a98add2d3b66e2fda95b5b2a667aa9dac7e59cc1d46d30e818"), "Generic");
			var info = BaseEncoding.base16().ignoreCase().decode("4f6465206f6e2061204772656369616e2055726e");
			context = hpke.keySchedule((byte) 0x00, sharedSecret, info, new byte[0], new byte[0]);
		}

		@ParameterizedTest
		@CsvSource(value = {
				"4265617574792069732074727574682c20747275746820626561757479, 436f756e742d30, 170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200aafcc6d80ea4c795a7c5b841a",
				"4265617574792069732074727574682c20747275746820626561757479, 436f756e742d31, d9ee248e220ca24ac00bbbe7e221a832e4f7fa64c4fbab3945b6f3af0c5ecd5e16815b328be4954a05fd352256",
				"4265617574792069732074727574682c20747275746820626561757479, 436f756e742d32, 142cf1e02d1f58d9285f2af7dcfa44f7c3f2d15c73d460c48c6e0e506a3144bae35284e7e221105b61d24e1c7a",
		})
		public void testKeySchedule(@Hex byte[] pt, @Hex byte[] aad, @Hex byte[] ct) {
			var result = context.seal(aad, pt);
			Assertions.assertArrayEquals(ct, result);
		}
	}

}