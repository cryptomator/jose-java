package org.cryptomator.jose.hpke;

import com.google.common.io.BaseEncoding;
import org.cryptomator.jose.Psk;
import org.cryptomator.jose.util.Curve;
import org.cryptomator.jose.util.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mockito;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.ECPrivateKeySpec;

class HPKETest {

	private static final BaseEncoding HEX = BaseEncoding.base16().ignoreCase();

	// test vectors from https://www.rfc-editor.org/rfc/rfc9180#appendix-A.3 (hpke0) and https://www.rfc-editor.org/rfc/rfc9180#appendix-A.6 (hpke2), base and PSK setups,
	// and https://www.ietf.org/archive/id/draft-ietf-hpke-pq-05.txt Appendix A.12.1 (hpke9's KEM and KDF, base setup)
	@Nested
	@DisplayName("test HPKE setup")
	public class Setup {

		// the recipient's private key from skRm, on the suite's curve
		private static PrivateKey ecPrivateKey(Curve curve, byte[] skRm) throws GeneralSecurityException {
			return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1, skRm), curve.getCurveParams()));
		}

		@ParameterizedTest(name = "{0} mode {1}")
		@CsvSource(value = {
				// suite, mode, skRm, enc, info, psk, psk_id, aad (Count-0), pt, ct
				"hpke0, base, f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2, 04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4, 4f6465206f6e2061204772656369616e2055726e, '', '', 436f756e742d30, 4265617574792069732074727574682c20747275746820626561757479, 5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434",
				"hpke0, psk, 438d8bcef33b89e0e9ae5eb0957c353c25a94584b0dd59c991372a75b43cb661, 04305d35563527bce037773d79a13deabed0e8e7cde61eecee403496959e89e4d0ca701726696d1485137ccb5341b3c1c7aaee90a4a02449725e744b1193b53b5f, 4f6465206f6e2061204772656369616e2055726e, 0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82, 456e6e796e20447572696e206172616e204d6f726961, 436f756e742d30, 4265617574792069732074727574682c20747275746820626561757479, 90c4deb5b75318530194e4bb62f890b019b1397bbf9d0d6eb918890e1fb2be1ac2603193b60a49c2126b75d0eb",
				"hpke2, base, 01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c27196a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b2462847, 040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0, 4f6465206f6e2061204772656369616e2055726e, '', '', 436f756e742d30, 4265617574792069732074727574682c20747275746820626561757479, 170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200aafcc6d80ea4c795a7c5b841a",
				"hpke2, psk, 011bafd9c7a52e3e71afbdab0d2f31b03d998a0dc875dd7555c63560e142bde264428de03379863b4ec6138f813fa009927dc5d15f62314c56d4e7ff2b485753eb72, 040085eff0835cc84351f32471d32aa453cdc1f6418eaaecf1c2824210eb1d48d0768b368110fab21407c324b8bb4bec63f042cfa4d0868d19b760eb4beba1bff793b30036d2c614d55730bd2a40c718f9466faf4d5f8170d22b6df98dfe0c067d02b349ae4a142e0c03418f0a1479ff78a3db07ae2c2e89e5840f712c174ba2118e90fdcb, 4f6465206f6e2061204772656369616e2055726e, 0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82, 456e6e796e20447572696e206172616e204d6f726961, 436f756e742d30, 4265617574792069732074727574682c20747275746820626561757479, de69e9d943a5d0b70be3359a19f317bd9aca4a2ebb4332a39bcdfc97d5fe62f3a77702f4822c3be531aa7843a1",
		})
		@DisplayName("setupR derives the recipient context from enc and skRm and opens the vector's first ciphertext")
		public void testSetupR(String suite, String mode, @Hex byte[] skRm, @Hex byte[] enc, @Hex byte[] info, @Hex byte[] psk, @Hex byte[] pskId, @Hex byte[] aad, @Hex byte[] pt, @Hex byte[] ct) throws Exception {
			var hpke = suite.equals("hpke0") ? HPKE.hpke0() : HPKE.hpke2();
			var skR = ecPrivateKey(suite.equals("hpke0") ? Curve.P256 : Curve.P521, skRm);
			var pskOrNull = psk.length == 0 ? null : new Psk(new SecretKeySpec(psk, "Generic"), pskId);
			try (var ctx = hpke.setupR(enc, skR, info, pskOrNull)) {
				Assertions.assertArrayEquals(pt, ctx.open(aad, ct));
			}
		}

		@Test
		@DisplayName("setupS with the vector's ikmE reproduces enc for hpke9 (MLKEM768-X25519)")
		public void testSetupS() throws Exception {
			// draft-ietf-hpke-pq A.12.1: the 64-byte ikmE is the hybrid KEM's encapsulation seed, consumed as two 32-byte draws (ML-KEM m, then the X25519 ephemeral secret)
			var ikmE = HEX.decode("ac9639cf4581ac270569ed0fd1f4ab0feb59db2956c91c38fd1744768102f69d29ad8d4e9fda6043676fa808d148fd448397fce724141dd9b8e9827d274a9fa5");
			var info = HEX.decode("34663634363532303666366532303631323034373732363536333639363136653230353537323665");
			var pkRm = HEX.decode("""
				4b9531fb494a29413d0ab36a92c7749d5b409a137f1a05c1385a6818308bd3d3\
				2f1065b73cb9a2fe9b77e74b9bb71a4a1f0aa01568687cf413893951d5e983e3\
				9904d0f3ac2cf457297741cb2658123ac5b0116863356b4b55551c5bb56faa9c\
				80a62417ea90dcd683601c5d2a977d0d74010f975c15622d01451d97234761c3\
				c8ff185c37a11acfc0c5fb311b2660c7ec28438498475d2c2dea12ac0387ce3e\
				c4669450302fca9a0ab93bd7cba2879c730bc17d6b5417c383c1f90b98073433\
				22f85d89abb16686bdf82176b7b36284678f017990ba4a724e36013bb38e5cc7\
				62c6e8c4127536b44659e9890608d2bd355148d5e3024842011c800c5ff72e20\
				da517aa669c1c78ec5a727129692ddec53d4d5aaa35016d63482d0a835977ca0\
				bff350ebf7b4317259d25a03511abcc5d631c979cb1c18bb829c257dcb038c50\
				85105aa88e5744e9507a247877796693f1631469f29dfab7a5d1ccb818c03ff6\
				52c4a896b9aa9264192b2f316973eca345c1f29ad6d9004e6a76afec630208ad\
				6bc058eeb81a1380ce567b57ec24a1f4c725611591e85a8bd0d8a306e32fa700\
				2fdb4c9ac9d02c73f557bb9c0a5f55295c33b9adbc4469a6a321eb39dbdb13fd\
				44a556200e33184fa44346741c12fe097b22c778fa25681d954da3843a609a1c\
				cf38478658883bfa6b314b6b93e11105884a59968a3cf89beff4717db7ac938b\
				89683bc588c6553389b53ca744099741f1d96e84ab93aeabb10e4b5d1269244f\
				a93b5ff27298872346733e38c48e92f817e1e98c61c220a1069a370581064646\
				3de7076c207d5d40b7dd812f58d8acf171900d7b8d9fc56f1c2929dbecb76580\
				554ba6b0b0447a8f6a6028f4cbb1933a58a26186cc4671c8caa6286d9124cb53\
				b82e12d90beb792cec4c556dac44c49a37dd49c2d42a917578ac08a51699331c\
				79babb43ec2a3647cc37db9316920693e194990baa7443a507104d3b62b015a1\
				99432aa606b4613f8cc63bd0565d66ce41d59b273bb6cdb95ebdd255029cbf6f\
				6221aba898f2a8868239975dd00c9a520b394849df134b318cb4e2b25fad4b0b\
				92d0c742bb3bd0c8c98ca2739048277d4b2056f3063895613d0a06a3d9a3bb86\
				cf47d8158d10cc6537008a7469f3fa0609604d896918e4676598232b30d9ca52\
				0ab308610f92d7b4cfbc3dcbe14cf90c925000501737a5b0f61f98006ecc7c21\
				e934c547e4800d54b2b578c9b4f435eac666094720fd45862a07a0121c0971b5\
				7b3fb69dc2c4b47dfbb47504295cd58adca7c0da5244dd7550576545b214c937\
				96a9c0458b3d887947f8bfa88959e7f1c72821548eba7ea9f74a787c2b40b962\
				ab58835a52524a94079a61284d7acb4943a54a117fc71b94776b732a644f66c4\
				51fbe34593a44d57fb21348799608959fad5c84e990951aca92c8bc68e084d2d\
				596307f586be8cb3e043507be17e70312156eb6e464cc530377d23f32a48fb69\
				21ab320a324fefa807c3cb262c460d9c1c8a23c9314cc3847fccc66c9519ba27\
				56f9956cedb8b42a38cd25f7237cc7ba5d50c8c2ac446fb7a4a76762c5f151d0\
				4682122057e793851a3496d5177782c4afe2688a7ae2a198156d0cdcb4c64c8d\
				282661abe19ffc2ca793ee9a2c190c5c6852d1d743384730c92c1bd82d433364\
				2a14f7e3cdd98b1791c98c1a09d3a0dd71b1e253cfc077801a0c2729f53a3023""");
			var expectedEnc = HEX.decode("""
				b0e05d539064754e11737ec32a268888b7fd7ccc11cdb3465860b26e75a5976b1\
				e586c83503332c395cc312278d3bd6a8118db9718397dec4bf7a7f0ddc1d9edc0\
				d0072b5bd8fe4861d6a01022cb3f30bac913753c60ce38fe3c322d60ad4bdc416\
				82b292bae49226e1b01736877d232034170046b4058111d12285c47b0a3efae9e\
				59654d3a7ee637d4b2fb00f17bd9337bf98cb59acf2ae53db40ca11910bfb639b\
				82b15d9fd4be09df8d5e7b3acafa9cd24df808ea8557e86c325d49387ac8b2b96\
				16d1f76efb6fd026345077641d7fde4ad3a83ff10f67de3eb4ec48f3045ed2032\
				c3a9ec9642cb70bb7bc27d0b56f0a6b323506b8d25c412bfd25897f228122bafe\
				2e5f8e55112c9f8e7c29d6d2498ace41742b7fd0e31a12afb2bf1beebcf63e387\
				b0826e5a69594293dc2f241cf7dfa8cf27391680f3d72e8c90fded4605058168c\
				e313a9de059d1a7e34f8016e62f9c824f440245498f463420b7736446b8fba0f8\
				848b00094cae0749d2f2fc6506511c7a43774eef264fb3f8b20c46f50e394a325\
				dd2de4b92aeab2db9d8f29e7e547766ebcf78000a1d33a74d0738f693e6d2389f\
				6b6ec90a608b50f07608c417e10f6f7ba0f0e489faa6bb93b78a189ce8a020358\
				57628c44f3edbdcb5b1a61c0864209b5bafb7ee9900605321505bcd6e1579f62a\
				e97ada8c030ec7fb3591142348739b3aa3ceea934b0f48619011301a2997f070d\
				e0a064cff27beb55543ba9447e6ac0e94dd171ac471ed3f773c4e34e9442c91da\
				655db39895a2c4f290e900b0c3b37691363a1ac5c78db70750ee0ef54f80ef631\
				cfd920d78ee1686f67536cbf1a74fe19f90c20eef96b02e4e34030a0ea833179d\
				4ae5a6c17c423271b4ad59f9045453a876561275d93d82a87af02c15a5513d853\
				7d954fb42db00edaabf8853840f00bc618432c6a9cd94b990549a35bdab4b1be7\
				a101862a3e7aa36f24513314751b2a6648f7552a1672decbca45717098c6808f1\
				2f341139ab75b5af14f895359b1152f638a3cbaacdb355ecd1af2daa5ae121d2d\
				c68c13713dd99f738e6c6d9c7409365dab6027ac1a7a71e0e6d2075a1593cae0a\
				664ab04cb0ab0711b15a5836e1eb40323fb60477215fd40f9b6b52ac7b2e73dde\
				487d729dbc3c7f976adbb28edcca8948b1a22f11943d367452e817f20ed27d4fe\
				b5341e4078164bb0010643d91fad31aee0c446274cc511501ecd929f83e8489dc\
				385cd1d2173a7e63791d5a7eb7d0115389e9a604a999a2a9b443655876187cb06\
				0ea8bf5272fd06b85a33545ffd7ec6e76e866f6f58c9f3214f16125bd541cf0dd\
				22a40042e19abc47462f7bee257958d330a74f6abc17c3dc1f23fd7da0b274eab\
				80dd6691c94ed5694cfbbce7d25e3a37b94358b87b57777ebf82d9a852301e335\
				3bf6356f26eb3d293ac97477b34734d7c1efaebfd2c22d7820ecff59b7da55ccd\
				0f2a54e645064612b716736543948bfb20234ef9d5a61e0697d8abc940711632f\
				56a14177de163c7d0b1788a0cb17272175ab893370766d75d28680cc2593902aa\
				fcc6ce2f25e3b71a9c1ff5f0871a0c""");
			var random = Mockito.mock(SecureRandom.class);
			Mockito.doAnswer(invocation -> {
				System.arraycopy(ikmE, 0, invocation.<byte[]>getArgument(0), 0, 32);
				return null;
			}).doAnswer(invocation -> {
				System.arraycopy(ikmE, 32, invocation.<byte[]>getArgument(0), 0, 32);
				return null;
			}).when(random).nextBytes(Mockito.any());

			var sender = HPKE.hpke9().setupS(new XwingPublicKey(pkRm), info, null, random);
			try (var ctx = sender.context()) {
				Assertions.assertArrayEquals(expectedEnc, sender.enc());
				Mockito.verify(random, Mockito.times(2)).nextBytes(Mockito.any());
			}
		}

	}

	// test vectors from https://www.rfc-editor.org/rfc/rfc9180#appendix-A.3.2 (hpke0) and https://www.rfc-editor.org/rfc/rfc9180#appendix-A.6.2 (hpke2), mode_psk
	@Nested
	@DisplayName("test HPKE key schedule in mode_psk")
	public class KeySchedulePsk {

		private static final byte[] INFO = hex("4f6465206f6e2061204772656369616e2055726e");
		private static final byte[] PSK = hex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
		private static final byte[] PSK_ID = hex("456e6e796e20447572696e206172616e204d6f726961");

		private static byte[] hex(String s) {
			return BaseEncoding.base16().ignoreCase().decode(s);
		}

		@ParameterizedTest
		@CsvSource(value = {
				"436f756e742d30, 90c4deb5b75318530194e4bb62f890b019b1397bbf9d0d6eb918890e1fb2be1ac2603193b60a49c2126b75d0eb",
				"436f756e742d31, 9e223384a3620f4a75b5a52f546b7262d8826dea18db5a365feb8b997180b22d72dc1287f7089a1073a7102c27",
				"436f756e742d32, adf9f6000773035023be7d415e13f84c1cb32a24339a32eb81df02be9ddc6abc880dd81cceb7c1d0c7781465b2",
		})
		@DisplayName("A.3.2: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM")
		public void testHpke0(@Hex byte[] aad, @Hex byte[] ct) {
			var sharedSecret = new DestroyableSecretKey(hex("2e783ad86a1beae03b5749e0f3f5e9bb19cb7eb382f2fb2dd64c99f15ae0661b"), "Generic");
			try (var ctx = HPKE.hpke0().keySchedule(HPKE.MODE_PSK, sharedSecret, INFO, PSK, PSK_ID)) {
				ctx.sequence = Integer.parseInt(new String(aad, java.nio.charset.StandardCharsets.US_ASCII).substring("Count-".length()));
				Assertions.assertArrayEquals(ct, ctx.seal(aad, hex("4265617574792069732074727574682c20747275746820626561757479")));
			}
		}

		@ParameterizedTest
		@CsvSource(value = {
				"436f756e742d30, de69e9d943a5d0b70be3359a19f317bd9aca4a2ebb4332a39bcdfc97d5fe62f3a77702f4822c3be531aa7843a1",
				"436f756e742d31, 77a16162831f90de350fea9152cfc685ecfa10acb4f7994f41aed43fa5431f2382d078ec88baec53943984553e",
				"436f756e742d32, f1d48d09f126b9003b4c7d3fe6779c7c92173188a2bb7465ba43d899a6398a333914d2bb19fd769d53f3ec7336",
		})
		@DisplayName("A.6.2: DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM")
		public void testHpke2(@Hex byte[] aad, @Hex byte[] ct) {
			var sharedSecret = new DestroyableSecretKey(hex("0d52de997fdaa4797720e8b1bebd3df3d03c4cf38cc8c1398168d36c3fc7626428c9c254dd3f9274450909c64a5b3acbe45e2d850a2fd69ac0605fe5c8a057a5"), "Generic");
			try (var ctx = HPKE.hpke2().keySchedule(HPKE.MODE_PSK, sharedSecret, INFO, PSK, PSK_ID)) {
				ctx.sequence = Integer.parseInt(new String(aad, java.nio.charset.StandardCharsets.US_ASCII).substring("Count-".length()));
				Assertions.assertArrayEquals(ct, ctx.seal(aad, hex("4265617574792069732074727574682c20747275746820626561757479")));
			}
		}

		@org.junit.jupiter.api.Test
		@DisplayName("VerifyPSKInputs: PSK inputs must be consistent with the mode")
		public void testVerifyPskInputs() {
			var sharedSecret = new DestroyableSecretKey(new byte[32], "Generic");
			var hpke = HPKE.hpke0();
			Assertions.assertThrows(IllegalArgumentException.class, () -> hpke.keySchedule(HPKE.MODE_PSK, sharedSecret, INFO, PSK, new byte[0]), "psk without psk_id");
			Assertions.assertThrows(IllegalArgumentException.class, () -> hpke.keySchedule(HPKE.MODE_PSK, sharedSecret, INFO, new byte[0], PSK_ID), "psk_id without psk");
			Assertions.assertThrows(IllegalArgumentException.class, () -> hpke.keySchedule(HPKE.MODE_BASE, sharedSecret, INFO, PSK, PSK_ID), "PSK provided in mode_base");
			Assertions.assertThrows(IllegalArgumentException.class, () -> hpke.keySchedule(HPKE.MODE_PSK, sharedSecret, INFO, new byte[0], new byte[0]), "no PSK in mode_psk");
			Assertions.assertThrows(UnsupportedOperationException.class, () -> hpke.keySchedule((byte) 0x02, sharedSecret, INFO, new byte[0], new byte[0]), "mode_auth");
		}

	}

	// test vectors from https://www.rfc-editor.org/rfc/rfc9180#appendix-A.6.2.1
	@Nested
	@DisplayName("test HPKE key schedule")
	public class KeySchedule {

		private static HPKE.Context context;

		@BeforeAll
		public static void setup() {
			var hpke = HPKE.hpke2(); // DHKEM(P-521, HKDF-SHA512) + HKDF-SHA512 + AES-256-GCM
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
