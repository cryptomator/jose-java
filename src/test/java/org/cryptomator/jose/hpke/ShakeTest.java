package org.cryptomator.jose.hpke;

import com.google.common.io.BaseEncoding;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/// Test vectors from [draft-ietf-hpke-pq, Appendix A.12](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05#appendix-A.12)
/// (MLKEM768-X25519, SHAKE256, ChaCha20Poly1305, mode_base)
class ShakeTest {

	private static final BaseEncoding HEX = BaseEncoding.base16().ignoreCase();

	// suite_id = "HPKE" || kem_id 0x647a || kdf_id 0x0011 || aead_id 0x0003
	private static final byte[] SUITE_ID = {'H', 'P', 'K', 'E', 0x64, 0x7a, 0x00, 0x11, 0x00, 0x03};
	private static final byte[] INFO = HEX.decode("34663634363532303666366532303631323034373732363536333639363136653230353537323665");
	private static final byte[] SHARED_SECRET = HEX.decode("c3b302f7ad7e13ab4713facdd0d8058507133e966519acca3af01ab2d5c96549");
	private static final byte[] KEY = HEX.decode("946a26bbe80fcb3b39e15971fd7f4b41f05826073fcc015c69a5c4a430166920");
	private static final byte[] BASE_NONCE = HEX.decode("df9df51376022d86761ae77c");

	@Test
	@DisplayName("CombineSecrets_OneStage with SHAKE256 derives key and base_nonce")
	public void testCombineSecrets() {
		var sharedSecret = new DestroyableSecret(SHARED_SECRET);

		// ChaCha20Poly1305: Nk = 32, Nn = 12
		var derived = Shake.SHAKE256.combineSecrets((byte) 0x00, sharedSecret, INFO, new byte[0], new byte[0], SUITE_ID, "Generic", 32, 12);

		Assertions.assertArrayEquals(KEY, derived.key().getEncoded());
		Assertions.assertArrayEquals(BASE_NONCE, derived.baseNonce());
	}

	@Test
	@DisplayName("X-Wing decapsulation of 'enc' followed by CombineSecrets_OneStage reproduces key and base_nonce")
	public void testDecapAndCombineSecrets() throws InvalidKeyException, DecapsulateException, NoSuchAlgorithmException {
		var skRm = HEX.decode("ade62d76461f5fb35b5de3419f10b4ab4cfd81512da8e8a094d51ad9746d9868");
		var enc = HEX.decode("""
				b0e05d539064754e11737ec32a268888b7fd7ccc11cdb3465860b26e75a5976b1e586c83503332c395cc312278d3bd6a\
				8118db9718397dec4bf7a7f0ddc1d9edc0d0072b5bd8fe4861d6a01022cb3f30bac913753c60ce38fe3c322d60ad4bdc\
				41682b292bae49226e1b01736877d232034170046b4058111d12285c47b0a3efae9e59654d3a7ee637d4b2fb00f17bd9\
				337bf98cb59acf2ae53db40ca11910bfb639b82b15d9fd4be09df8d5e7b3acafa9cd24df808ea8557e86c325d49387ac\
				8b2b9616d1f76efb6fd026345077641d7fde4ad3a83ff10f67de3eb4ec48f3045ed2032c3a9ec9642cb70bb7bc27d0b5\
				6f0a6b323506b8d25c412bfd25897f228122bafe2e5f8e55112c9f8e7c29d6d2498ace41742b7fd0e31a12afb2bf1bee\
				bcf63e387b0826e5a69594293dc2f241cf7dfa8cf27391680f3d72e8c90fded4605058168ce313a9de059d1a7e34f801\
				6e62f9c824f440245498f463420b7736446b8fba0f8848b00094cae0749d2f2fc6506511c7a43774eef264fb3f8b20c4\
				6f50e394a325dd2de4b92aeab2db9d8f29e7e547766ebcf78000a1d33a74d0738f693e6d2389f6b6ec90a608b50f0760\
				8c417e10f6f7ba0f0e489faa6bb93b78a189ce8a02035857628c44f3edbdcb5b1a61c0864209b5bafb7ee99006053215\
				05bcd6e1579f62ae97ada8c030ec7fb3591142348739b3aa3ceea934b0f48619011301a2997f070de0a064cff27beb55\
				543ba9447e6ac0e94dd171ac471ed3f773c4e34e9442c91da655db39895a2c4f290e900b0c3b37691363a1ac5c78db70\
				750ee0ef54f80ef631cfd920d78ee1686f67536cbf1a74fe19f90c20eef96b02e4e34030a0ea833179d4ae5a6c17c423\
				271b4ad59f9045453a876561275d93d82a87af02c15a5513d8537d954fb42db00edaabf8853840f00bc618432c6a9cd9\
				4b990549a35bdab4b1be7a101862a3e7aa36f24513314751b2a6648f7552a1672decbca45717098c6808f12f341139ab\
				75b5af14f895359b1152f638a3cbaacdb355ecd1af2daa5ae121d2dc68c13713dd99f738e6c6d9c7409365dab6027ac1\
				a7a71e0e6d2075a1593cae0a664ab04cb0ab0711b15a5836e1eb40323fb60477215fd40f9b6b52ac7b2e73dde487d729\
				dbc3c7f976adbb28edcca8948b1a22f11943d367452e817f20ed27d4feb5341e4078164bb0010643d91fad31aee0c446\
				274cc511501ecd929f83e8489dc385cd1d2173a7e63791d5a7eb7d0115389e9a604a999a2a9b443655876187cb060ea8\
				bf5272fd06b85a33545ffd7ec6e76e866f6f58c9f3214f16125bd541cf0dd22a40042e19abc47462f7bee257958d330a\
				74f6abc17c3dc1f23fd7da0b274eab80dd6691c94ed5694cfbbce7d25e3a37b94358b87b57777ebf82d9a852301e3353\
				bf6356f26eb3d293ac97477b34734d7c1efaebfd2c22d7820ecff59b7da55ccd0f2a54e645064612b716736543948bfb\
				20234ef9d5a61e0697d8abc940711632f56a14177de163c7d0b1788a0cb17272175ab893370766d75d28680cc2593902\
				aafcc6ce2f25e3b71a9c1ff5f0871a0c""");

		var kem = KEM.getInstance("X-Wing", XwingProvider.INSTANCE);
		var sharedSecret = kem.newDecapsulator(new XwingPrivateKey(skRm)).decapsulate(enc);
		Assertions.assertArrayEquals(SHARED_SECRET, sharedSecret.getEncoded());

		var derived = Shake.SHAKE256.combineSecrets((byte) 0x00, sharedSecret, INFO, new byte[0], new byte[0], SUITE_ID, "Generic", 32, 12);

		Assertions.assertArrayEquals(KEY, derived.key().getEncoded());
		Assertions.assertArrayEquals(BASE_NONCE, derived.baseNonce());
	}

	// combineSecrets zeroes the encoded shared secret it obtains, so hand it a copy to keep the test vector intact
	private record DestroyableSecret(byte[] secret) implements SecretKey {

		@Override
		public String getAlgorithm() {
			return "Generic";
		}

		@Override
		public String getFormat() {
			return "RAW";
		}

		@Override
		public byte[] getEncoded() {
			return secret.clone();
		}
	}

}
