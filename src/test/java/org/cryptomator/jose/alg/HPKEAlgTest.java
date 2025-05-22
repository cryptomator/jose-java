package org.cryptomator.jose.alg;

import com.google.common.io.BaseEncoding;
import org.cryptomator.jose.util.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.spec.SecretKeySpec;

class HPKEAlgTest {

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