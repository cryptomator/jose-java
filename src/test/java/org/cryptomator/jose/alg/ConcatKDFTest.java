package org.cryptomator.jose.alg;

import org.cryptomator.jose.util.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class ConcatKDFTest {

	@ParameterizedTest
	@CsvSource({
			// test vectors from https://github.com/patrickfav/singlestep-kdf/wiki/NIST-SP-800-56C-Rev1:-Non-Official-Test-Vectors
			"3f892bd8b84dae64a782a35f6eaa8f00, 2, ec3f1cd873d28858a58cc39e, a7c0",
			"3f892bd8b84dae64a782a35f6eaa8f00, 30, ec3f1cd873d28858a58cc39e, a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a9",
			"3f892bd8b84dae64a782a35f6eaa8f00, 32, ec3f1cd873d28858a58cc39e, a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91",
			"3f892bd8b84dae64a782a35f6eaa8f00, 34, ec3f1cd873d28858a58cc39e, a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491",
			"3f892bd8b84dae64a782a35f6eaa8f00, 68, ec3f1cd873d28858a58cc39e, a7c0665298252531e0db37737a374651b368275f2048284d16a166c6d8a90a91a491c16f49641b9f516a03d9d6d0f4fe7b81ffdf1c816f40ecd74aed8eda2b8a3c714fa0",
			// test vectors from https://www.rfc-editor.org/rfc/rfc7518#appendix-C
			"9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4, 16, 000000074131323847434d00000005416c69636500000003426f6200000080, 56aa8deaf8236d205c2228cd71a7101a"
	})
	public void testConcatKDFWithSha256(@Hex byte[] z, int keyLength, @Hex byte[] otherInfo, @Hex byte[] expected) {
		var derivedKey = ConcatKDF.sha256().kdf(z, keyLength, otherInfo);

		Assertions.assertArrayEquals(expected, derivedKey);
	}

}