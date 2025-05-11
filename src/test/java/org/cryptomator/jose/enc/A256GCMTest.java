package org.cryptomator.jose.enc;

import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.util.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class A256GCMTest {

	// test vectors 1-10 from wycheproof: https://github.com/C2SP/wycheproof/blob/df4e933efef449fc88af0c06e028d425d84a9495/testvectors/aes_gcm_test.json
	@DisplayName("Encrypt with A256GCM")
	@ParameterizedTest
	@CsvSource({
			"5b9604fe14eadba931b0ccf34843dab9, 028318abc1824029138141a2, '', 001d0c231287c1182784554ca3a21908, 26073cc1d851beff176384dc9896d5ff, 0a3ea7a5487cb5f7d70fb6c58d038554",
			"5b9604fe14eadba931b0ccf34843dab9, 921d2507fa8007b7bd067d34, 00112233445566778899aabbccddeeff, 001d0c231287c1182784554ca3a21908, 49d8b9783e911913d87094d1f63cc765, 1e348ba07cca2cf04c618cb4d43a5b92",
			"aa023d0478dcb2b2312498293d9a9129, 0432bc49ac34412081288127, aac39231129872a2, 2035af313d1346ab00154fea78322105, eea945f3d0f98cc0fbab472a0cf24e87, 4bb9b4812519dadf9e1232016d068133",
			"bedcfb5a011ebc84600fcb296c15af0d, 438a547a94ea88dce46c6c85, '', '', '', 960247ba5cde02e41a313c4c0136edc3",
			"384ea416ac3c2f51a76e7d8226346d4e, b30c084727ad1c592ac21d12, '', 35, 54, 7c1e4ae88bb27e5638343cb9fd3f6337",
			"cae31cd9f55526eb038241fc44cac1e5, b5e006ded553110e6dc56529, '', d10989f2c52e94ad, a036ead03193903f, 3b626940e0e9f0cbea8e18c437fd6011",
			"dd6197cd63c963919cf0c273ef6b28bf, ecb0c42f7000ef0e6f95f24d, '', 4dcc1485365866e25ac3f2ca6aba97, 8a9992388e735f80ee18f4a63c10ad, 1486a91cccf92c9a5b00f7b0e034891c",
			"ffdf4228361ea1f8165852136b3480f7, 0e1666f2dc652f7708fb8f0d, '', 25b12e28ac0ef6ead0226a3b2288c800, f7bd379d130477176b8bb3cb23dbbbaa, 1ee6513ce30c7873f59dd4350a588f42",
			"c15ed227dd2e237ecd087eaaaad19ea4, 965ff6643116ac1443a2dec7, '', fee62fde973fe025ad6b322dcdf3c63fc7, 0de51fe4f7f2d1f0f917569f5c6d1b009c, 6cd8521422c0177e83ef1b7a845d97db",
			"a8ee11b26d7ceb7f17eaa1e4b83a2cf6, fbbc04fd6e025b7193eb57f6, '', c08f085e6a9e0ef3636280c11ecfadf0c1e72919ffc17eaf, 7cd9f4e4f365704fff3b9900aa93ba54b672bac554275650, f4eb193241226db017b32ec38ca47217",
	})
	public void testEncrypt(@Hex byte[] key, @Hex byte[] iv, @Hex byte[] aad, @Hex byte[] plaintext, @Hex byte[] ciphertext, @Hex byte[] tag) {
		var alg = new A256GCM();

		var result = alg.encrypt(key, iv, aad, plaintext);

		Assertions.assertArrayEquals(ciphertext, result.ciphertext());
		Assertions.assertArrayEquals(tag, result.tag());
	}

	// test vectors 1-10 from wycheproof: https://github.com/C2SP/wycheproof/blob/df4e933efef449fc88af0c06e028d425d84a9495/testvectors/aes_gcm_test.json
	@DisplayName("Decrypt with A256GCM")
	@ParameterizedTest
	@CsvSource({
			"5b9604fe14eadba931b0ccf34843dab9, 028318abc1824029138141a2, '', 001d0c231287c1182784554ca3a21908, 26073cc1d851beff176384dc9896d5ff, 0a3ea7a5487cb5f7d70fb6c58d038554",
			"5b9604fe14eadba931b0ccf34843dab9, 921d2507fa8007b7bd067d34, 00112233445566778899aabbccddeeff, 001d0c231287c1182784554ca3a21908, 49d8b9783e911913d87094d1f63cc765, 1e348ba07cca2cf04c618cb4d43a5b92",
			"aa023d0478dcb2b2312498293d9a9129, 0432bc49ac34412081288127, aac39231129872a2, 2035af313d1346ab00154fea78322105, eea945f3d0f98cc0fbab472a0cf24e87, 4bb9b4812519dadf9e1232016d068133",
			"bedcfb5a011ebc84600fcb296c15af0d, 438a547a94ea88dce46c6c85, '', '', '', 960247ba5cde02e41a313c4c0136edc3",
			"384ea416ac3c2f51a76e7d8226346d4e, b30c084727ad1c592ac21d12, '', 35, 54, 7c1e4ae88bb27e5638343cb9fd3f6337",
			"cae31cd9f55526eb038241fc44cac1e5, b5e006ded553110e6dc56529, '', d10989f2c52e94ad, a036ead03193903f, 3b626940e0e9f0cbea8e18c437fd6011",
			"dd6197cd63c963919cf0c273ef6b28bf, ecb0c42f7000ef0e6f95f24d, '', 4dcc1485365866e25ac3f2ca6aba97, 8a9992388e735f80ee18f4a63c10ad, 1486a91cccf92c9a5b00f7b0e034891c",
			"ffdf4228361ea1f8165852136b3480f7, 0e1666f2dc652f7708fb8f0d, '', 25b12e28ac0ef6ead0226a3b2288c800, f7bd379d130477176b8bb3cb23dbbbaa, 1ee6513ce30c7873f59dd4350a588f42",
			"c15ed227dd2e237ecd087eaaaad19ea4, 965ff6643116ac1443a2dec7, '', fee62fde973fe025ad6b322dcdf3c63fc7, 0de51fe4f7f2d1f0f917569f5c6d1b009c, 6cd8521422c0177e83ef1b7a845d97db",
			"a8ee11b26d7ceb7f17eaa1e4b83a2cf6, fbbc04fd6e025b7193eb57f6, '', c08f085e6a9e0ef3636280c11ecfadf0c1e72919ffc17eaf, 7cd9f4e4f365704fff3b9900aa93ba54b672bac554275650, f4eb193241226db017b32ec38ca47217",
	})
	public void testDecrypt(@Hex byte[] key, @Hex byte[] iv, @Hex byte[] aad, @Hex byte[] plaintext, @Hex byte[] ciphertext, @Hex byte[] tag) throws JoseDecryptException {
		var alg = new A256GCM();

		var result = alg.decrypt(key, iv, aad, ciphertext, tag);

		Assertions.assertArrayEquals(plaintext, result);
	}

}