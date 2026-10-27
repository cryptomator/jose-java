package org.cryptomator.jose.alg;

import java.security.KeyPair;

import javax.crypto.spec.SecretKeySpec;

import org.cryptomator.jose.util.Curve;

import org.cryptomator.jose.Psk;

import org.cryptomator.jose.JoseException;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.cryptomator.jose.Alg;
import org.cryptomator.jose.DecryptionAlg;
import org.cryptomator.jose.JWE;
import org.cryptomator.jose.JWK;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.JoseParseException;
import org.cryptomator.jose.hpke.HPKE;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;

class HPKEIntegratedAlgTest {

	// the same Fellowship quote, but the two drafts differ in their choice of dash
	private static final String EXPECTED_PAYLOAD_HYPHEN = "You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";
	private static final String EXPECTED_PAYLOAD_EN_DASH = "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";
	private static final String EXPECTED_AAD = "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc"; // "The Fellowship of the Ring"

	/// test vectors from [draft-ietf-jose-hpke-encrypt, Appendix A.1](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt-22#appendix-A.1)
	@Nested
	@DisplayName("HPKE-0 test vectors")
	class Hpke0 {

		static final String PRIVATE_JWK = """
				{
				  "kty": "EC",
				  "crv": "P-256",
				  "x": "qy-BxXhaelX9Fqe8muRTu8HhseHYgMMGxyfAnIy0MC0",
				  "y": "ctfHN7Y4pkj7vZI-sgJ6BqsYwG-PDnB8j7TsfzHHJOI",
				  "d": "aAKxBMAkNm2AZDGv7LN5yodDwahJ5rKbrgiiz3dUIH4",
				  "alg": "HPKE-0",
				  "use": "enc",
				  "kid": "KfvD-eYaynUKba0ow-v9uoEV-twV6mYDyiAOWO6LoPM"
				}
				""";

		private static final String FLATTENED_JWE = """
				{
				  "protected": "eyJhbGciOiJIUEtFLTAiLCJraWQiOiJLZnZELWVZYXluVUtiYTBvdy12OXVvRVYtdHdWNm1ZRHlpQU9XTzZMb1BNIn0",
				  "aad": "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc",
				  "encrypted_key": "BNC1LPfAH7I5Fxi7X7lrQLFkdpZcSGoXpBw4FYvCY1wZqAX53caa-lyNLPHkzwQMAMFHoOoN_TRGSzb2Gw4aDlA",
				  "ciphertext": "I0sH6mQa6r-mgLHqI23-wzBmsTULQoNtANiHF_incW5y5BIB7qo0XN3NoOqf1IvH1UEfE1_Tu9Baf6M3z_E9eJK1oDV1Q8A6VnZUnhj0cf2UNQhufoVJOlpbPolLiecxwitIqYKPKfzJmG1uZ7lA0xUAiNPkUR9OSHpLYr9HWAa1DWDbczWOMtFnxCJwd-PfyjX5-5-X6kAcdj5z-Kx4losmN2k7r2T1BUnHNnZlSgcz5nSZBxvKqkXX3xl0Tw9ys--37IJD7UcIFfST6b0PXHzuKSw-attSD_67SRcpcxUTm3nyvtroYF8sg0ztQLuNkC-gwe7-uxPNO2iBDIypgImhvlTaAEcuHJDtFgU5geIXFMAlMDAg7cSk4ssR"
				}
				""";

		private DecryptionAlg alg;

		@BeforeEach
		void setup() throws JoseParseException {
			var privateKey = (ECPrivateKey) JWK.parsePrivate(PRIVATE_JWK).privateKey();
			this.alg = new HPKEIntegratedAlg(HPKE.hpke0(), null, privateKey);
		}

		@Test
		@DisplayName("decrypt compact serialization")
		void decryptCompact() throws JoseParseException, JoseDecryptException {
			var jwe = """
					eyJhbGciOiJIUEtFLTAiLCJraWQiOiJLZnZELWVZYXluVUtiYTBvdy12OXVvRVYtdHdWNm1ZRHlpQU9XTzZMb1BNIn0.BKqU\
					aiyoPbH1jnjApcpjGqswg7npGSSXFcFv1nGaL6YYs3S27c8Yi5V5rsds91bV_UjdqzLlj2zuuAPWetLMab8..fO8VQt1Dsdg\
					tijGci90sO8sNvws6im8Yko4NnMWXVAM5GaHbHYRSGnjs6M7GnkcaTrEjy8cxDDLZFKTwMdYGOjYBsbTVVAoIImVd8tXZNjQ\
					swaPU8t8OP1jCwo6iw8t4-Hm6hCE61uzhEd_r9XkN4blHjrcAoCICcwqn_5lgJCTPQezJtiTAhrtHpC1quPA3aO2Pyhui5Cz\
					Otk967IC8v28jq6K7C3mbu-m10bo0aWqdybibCiiS5A89PXFWurW83HNnJFdoiqZRTtF4d_OAQ2Jq9FCrahrh43Xqp1z3HYj\
					f73_rOHYWXzv8jGorDAKjsPgxYN_9TgGUstjiRIMLj9dJXxqrPkRLQ4VSAzVWCNe5MabAR1sFFB5tx_gA.""";
			var decrypted = JWE.parse(jwe).decrypt(alg);
			Assertions.assertEquals(EXPECTED_PAYLOAD_HYPHEN, decrypted.payload());
		}

		@Test
		@DisplayName("decrypt flattened JSON serialization with AAD")
		void decryptFlattened() throws JoseParseException, JoseDecryptException {
			var decrypted = JWE.parse(FLATTENED_JWE).decrypt(alg);
			Assertions.assertEquals(EXPECTED_PAYLOAD_HYPHEN, decrypted.payload());
			Assertions.assertEquals(EXPECTED_AAD, decrypted.aad());
		}

		@Test
		@DisplayName("reject enc/ek headers injected into the unprotected header")
		void rejectInjectedEncHeader() throws JoseParseException {
			// an attacker (or an implementation of an outdated draft) must not be able to combine Integrated Encryption with enc/ek headers
			var json = JsonParser.parseString(FLATTENED_JWE).getAsJsonObject();
			var unprotected = new JsonObject();
			unprotected.addProperty("enc", "A128GCM");
			json.add("unprotected", unprotected);
			var parsed = JWE.parse(json.toString());
			var thrown = Assertions.assertThrows(JoseDecryptException.class, () -> parsed.decrypt(alg));
			// the specific reason survives as a suppressed exception on the "no matching recipient" failure
			Assertions.assertEquals(1, thrown.getSuppressed().length);
			Assertions.assertTrue(thrown.getSuppressed()[0].getMessage().contains("enc and ek headers must not be present"));
		}

		@Test
		@DisplayName("reject alg outside the protected header")
		void rejectUnprotectedAlg() throws JoseParseException {
			// draft §5: the protected header MUST contain alg; moving it to the unprotected header would take it out of the HPKE aad
			var json = JsonParser.parseString(FLATTENED_JWE).getAsJsonObject();
			var protectedHeader = JWE.parse(FLATTENED_JWE).parsedProtectedHeader();
			var algValue = protectedHeader.remove("alg");
			json.addProperty("protected", Base64.getUrlEncoder().withoutPadding().encodeToString(protectedHeader.toString().getBytes(StandardCharsets.UTF_8)));
			var unprotected = new JsonObject();
			unprotected.add("alg", algValue);
			json.add("unprotected", unprotected);
			var parsed = JWE.parse(json.toString());
			var thrown = Assertions.assertThrows(JoseDecryptException.class, () -> parsed.decrypt(alg));
			Assertions.assertEquals(1, thrown.getSuppressed().length);
			Assertions.assertTrue(thrown.getSuppressed()[0].getMessage().contains("protected header"));
		}

		@Test
		@DisplayName("reject more than one recipient")
		void rejectMultipleRecipients() throws JoseParseException {
			// draft §5: Integrated Encryption has exactly one recipient; a general JSON with the same encapsulation twice would otherwise decrypt via either entry
			var json = JsonParser.parseString(FLATTENED_JWE).getAsJsonObject();
			var encryptedKey = json.remove("encrypted_key");
			var recipients = new com.google.gson.JsonArray();
			for (int i = 0; i < 2; i++) {
				var recipient = new JsonObject();
				recipient.add("encrypted_key", encryptedKey);
				recipients.add(recipient);
			}
			json.add("recipients", recipients);
			var parsed = JWE.parse(json.toString());
			var thrown = Assertions.assertThrows(JoseDecryptException.class, () -> parsed.decrypt(alg));
			Assertions.assertEquals(2, thrown.getSuppressed().length);
			Assertions.assertTrue(thrown.getSuppressed()[0].getMessage().contains("exactly one recipient"));
		}

		@Test
		@DisplayName("reject non-empty iv/tag")
		void rejectNonEmptyIv() throws JoseParseException {
			var json = JsonParser.parseString(FLATTENED_JWE).getAsJsonObject();
			json.addProperty("iv", "hsc8LLwbgwf33MdT");
			var parsed = JWE.parse(json.toString());
			var thrown = Assertions.assertThrows(JoseDecryptException.class, () -> parsed.decrypt(alg));
			Assertions.assertEquals(1, thrown.getSuppressed().length);
			Assertions.assertTrue(thrown.getSuppressed()[0].getMessage().contains("iv and tag must be empty"));
		}

	}

	/// test vectors from [draft-ietf-jose-hpke-pq-pqt, Appendix A.3](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-pq-pqt-01#appendix-A.3)
	@Nested
	@DisplayName("HPKE-9 test vectors")
	class Hpke9 {

		static final String PRIVATE_JWK = """
				{
				  "kty": "AKP",
				  "alg": "HPKE-9",
				  "kid": "BeWp7Y5tolX2sSYMKIaG6WUVE-arTKcS2Ok8EgqFqrE",
				  "pub": "ZEbKruTLTRJZf-UygOWQwuBNzChq8yuhGTVITLeU7emGD9tF9oFEy1BP9hmBRWo84Zyjr8xlvkadCNyu5iOfuoIC7pA5JCc3A7BNp2ZK8TnNPTsYJ9BTicjChlIMMYKVSnk9WjCj3EqM90RaRiSHYxMUJ0VV8fY_06BqrODCwNO_6BYGaaxHszSAVparmkEiSQOZwyB6xsc0dsU2MGVGANQDBCu3NSs2gZmN1fslWpxzqyN4YtZhwkozcmsGztObngYHXEtgqpo44mKqXHfMBIxjvsqgZ-vNzGyp04OErotG5QOeu5gQZquZ4TlS7JqxjjN0ktJ9Wqofvlq1i0JG97VL7aJ0IHJpnFl8-4cbqwq7-Wan_9U0fJux18PBDBq3jkQiwLiXZOk9Klgin6BGwpx-JPedIOOEEEnKLpQwg3lOZGuHfXGCT5BkGfk4sVVR3dg7uMvC4yFS5ftvggIWfMPI4LV-3DECG-pDe1vEpQFE5EwSBHUhpyjAWuMEHbpTKau5oGmVAIYXRKZfZ3CIFQV3gHoBZdZQoRhEXzKmdkPB2jJI16FnFGUK_GSZYsXK68IUk_lEnihTadnBEhM78-wh9ZtAXQsKgQtUdWR7nFt6yWAkSQIegmJzzkEw4_FBrNYUIXC930h1dYi1sZw5ZHo3dmY3Viq4pLiiixN9LrdzV6RGIwR8fmpqbqNAc_cVsFePATiHnwBQ5kej1BLMAkUfYhJpX1lV-9tloZLA6JdkRoAeXnEvIxyY1TUYpugYuZUeERwlWygVnOidsIi_Apo1KAUm-TocR6m0zGtG2YQ07mUeI2yqbctcg6EvYVVBLDu_RJeLFyAw-Xd_WXgWNoIzoOM5CXLOtDCcJwMoLJknW1dgNxdFZHG1mQg9T5wBMbEBpjK8a9oOnfxVblik3eUHYkS7TVhKSqCOuyOBzDQuVtHAt9Q6OCoOguqUmJeBV4GSd5IPSnpCendqBjEKZ2JTkNwFkuqqbmilEnYMHEOtMUyveWZi6_qm2kPG7aVcjFV9U4pXZEuRIJcugvJUH3qw9UQ7smgqsaJMFzrDVsAGQWItDJxcEOgBdBTAiit99igYmAeEyNoK-GQ46OYsNzq5-CuCiCGJZKNObWhddnROkmY6jFG7K_k_RgvAj_aW0oPIEzGz0jBtZqVDMTFHF6d4q9erpHOaO8h9e7k2nnrGyHgkJYOPQImVrLNc93OEJ1qLzUSwJaho8KqwNlOHqDuJgmKoSfEhqXQRfIh68qNqZ6SC9JYJ_-lwpKk_TQUYxJUdRkHB9fgkBwyoGsi0nLpOhMinsIc32CMyHMqvBsc9DlSgmZOBgiovynEtj_gqdVZ3ZYwDAaSaXTG7wLMyNwBfVycm5TdMQeZs8dwu6pifo_UYzBhj1EY8u3IdS3OVajDKZqkw9zeTacE2kwVsCkDOK_y-wQXEvyFCbAYW3IANbpAuIwpirGJfFTWHIFEm1CqL4FXPt8a9DusGHQCuq3bEkCtpnRiOTGOqgVSZSWkuoxbGnluihrRc5NYY87PCvMSRVxthHPS6-Af2yP_HWMkcfu3DwNyCFxBJgfvtXGLFSm8Zq6EG4zipdIVLeDl-Mg6s_8jDce27ki2xqXVQWA",
				  "priv": "tQDSUt-Mgd0LNFiUK9VEluJnrtg057pCq97A54EdbiM"
				}
				""";

		private DecryptionAlg alg;

		@BeforeEach
		void setup() throws JoseParseException {
			this.alg = Alg.hpke9(JWK.parsePrivate(PRIVATE_JWK));
		}

		@Test
		@DisplayName("decrypt compact serialization")
		void decryptCompact() throws JoseParseException, JoseDecryptException {
			var jwe = """
					eyJhbGciOiJIUEtFLTkiLCJraWQiOiJCZVdwN1k1dG9sWDJzU1lNS0lhRzZXVVZFLWFyVEtjUzJPazhFZ3FGcXJFIn0.ZMY3\
					Ynj6V0Tflad99MujhmvSUTEYP-PETVMxSGfdKWjz1n2dvNmUCMfDS-pAzsh3lny2RyTHLFsUoX_Hl_hG4QYd1nZm4X9bgWpP\
					x8e5Mhbx9T8hGRbf8S1q3mkyLyIQNBtPW2KJMAzy6d5MQiJy98V4cL_-GFFUde8gvY1pIqfXSLC_BBmvnA2DddcGPvi3eKco\
					8PDY2HVNMQlCusFnnYVcRXiRc3tLJ2sAYIdavSJDqUV8QxiOqR6J0g_G0ngqPoP__bwNbF_UDU4_9flpBy8pQS2P9nBJLdYB\
					i5o_zwdUXTKCSgzUEvxrmr1YrGE7oPczjviXzBK-fbMWS7ShXFQ-ILzAccf2yb7hef76AduEi9mnS4D6SEsPTEpFUNIrljED\
					4J2QNuYOMlYCTb6Gen2h63FHZmTVMyXqhnKQUjelpg_qoD0L3ASUxRUC10YR8zidpA4MKIRGXwfN1eeqQc_M4hyurMXLBOSj\
					rZqCsKtk0KlgtFx7AmgZHULmYUcKZupfjCjPpMOAn3zmO_MF3NrsKtYofQyF3USoVfItSsu-KXDTU_b55EFZfD7ur_4X_Wg_\
					7h0GX_2SNzsRCyqNhmucBPej7Sm6spDjPfYXuyFgqrEOVVQU6wMcONJLxTktTxciYcXI6gaCOgXgr7zWAQmP2E9UqiAq80ya\
					aM5-WMwUUB1_VlruaqHy7s1cNBq3U0hC3a0C8_QVgxTYYIZa-IEsHjx2DoLAOgiDrfQYQPer1YVXg6A-q1lPPO-jcahyfUXv\
					PDsNfYJTRe1HvUXEW_IOZOJhodTyreSPLjvRXhw7MQ4ghScbKusuPOwP3GXB1mcRiG1V1dQumJ5PPD0-b4dO_9ygcZf46A1e\
					xcJrE5HeJ0SY6Ukue9uib4VEXeQi8HbS8hycC38qejW04FIZLukqhSXHST-pCoD1ztFd235WCIFQCsqOUOR6ZxHyO_Mnlujx\
					uYGoU_J7QBuuXRZMWVLo6rwKrUqOkJVqy9UpYFwTOOG1g795uCkprW78W-kTRfiWkVjPReO8skg3u_FpvUXdSIbJ-M40xUq1\
					9DsRN_RlFaMXX8b3m5NjDcBPJpPrVlN910izuecSJOalsPsrp0NWSXkQI42FFK9Wy0xIC7Fm8AZM-_5FnUkGyuqWSNLCkWPj\
					WWdK9NAnIkkHArv7BHvpQSm-FCeTgFCQIvVSlsjXU2-Nu55w-D0ToW6MPIVQHWtQKgUwJw97eQQ4Ni0Mgl61IeejrCaJBTfx\
					JzsM6X7evU-9IY61WJJAFI5BcmUlcpaHm0aLRuLMGLLmrKsvOfEj48AqTHdI13jL4KVME-bRYz87twX7GXpGmNLa0X3PGLus\
					Z9gH91xZhKu8rK29oSAJM3T4XRP5qO4_8ETE9qZ6-QAa-b5dmXgkcswHwbS09WzBAx1ePVVU_q-a8U-6HFaGswk9bheV0aoY\
					SPXK_J4PKVM-R7YbxTO1NiOviY3E0XGJJHMp8M4ONbAYO6laXw..W8wioV5NhSNz-rqzlPSWOPkjX-bVNx_vCiw9rguyL4dg\
					G-rOVJqyBOvnukWT9V1v_ZmtXYdi_oAhOmCSaF5_D1DYNWbpajOSX8m-j3nCjRaJdAf5N1r4XOw00o2BTdU9b1j6ZeJNB4I_\
					71HFoGTVCY11NJbbgQBzoxWpMDQkn8cCk9QkCOqukakoK7qRB_e2dJnujcGMTIr3s5n0gTZMkEaEAWdP3TNoQf-0YmCQS-4i\
					-6qo0nkcUUYCH64vASVh5zrPNgCODOoFd2HF65gGKEJrCEcVefLkYVCM3Zk2PPvOaUSI9eJqbKB9y9ieGxFcgnlLcw8bY-4l\
					6fKjg8mI1H2ZNVRXsRmO0ycR6_7zzBfHUNklpp1LiQ9wGiCTh3VOGA.""";
			var decrypted = JWE.parse(jwe).decrypt(alg);
			Assertions.assertEquals(EXPECTED_PAYLOAD_EN_DASH, decrypted.payload());
		}

		@Test
		@DisplayName("decrypt flattened JSON serialization with AAD")
		void decryptFlattened() throws JoseParseException, JoseDecryptException {
			var jwe = """
					{
					  "protected": "eyJhbGciOiJIUEtFLTkiLCJraWQiOiJCZVdwN1k1dG9sWDJzU1lNS0lhRzZXVVZFLWFyVEtjUzJPazhFZ3FGcXJFIn0",
					  "aad": "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc",
					  "encrypted_key": "FNPUnD-x_KD2ZlRpfS1i5otH3zXS0p5YqAX1IQXDg7KkVDfPrigLJiUX2olBxmMcer7yXyH1L1VMt3AnbWWHAH68JXG4maBWMtpy-ahh6X7k16JrzCzzQCuRWS2qDMNw_jjb7L_LiR6N9VigfKC63i8D5fL9P3y84jab77h5BFeH_px4XNXdj4IZpoQbrF496F3TMCpj0F7VIOPOH9Vjt6gH4sOAvkeuX5riGG9F0dhN67GmRHAeCZyW8ywvfzjADZnRG0_SX-bfcmICTJziIVy4KaEMH0YvmIrYmQe9jI-XKCIoeSQpXbvXQtniw6vWhPV5pDldRF89fshN1VIhTT2zsP9of5loHM9DJp7ac8SvhRIPm2GHocU9JtRN0MIkeUEqLMnJlp1dBJl3D3qwcOTvAO0A3ZA876Xu8Gsgcn5VsJj-O1AN2eB08BR3NNGDuuUsgxPVXQWyAFSQ_UlG7IVRp_8__NxfW4cbpCjcE9hvvlQD-xFS0a6rQOKImWKzwKmY8GiU2SUEAwN6rSPHr8JyGfh0YrA0--FgPuab6PPGrZ1qz427SQIxlJBCipWPLlhJzvbWUGCw0g8Tk2DQGnCBMZNc4lBNVhnKedQ57g6erNBh0MOZSXj-SLul57DSBXguw9jMUtsJZoF8PjIc-eSrQrZude3S9illlCRM1dfSaxPk825PQjBFlMnEb9qe-Uc65ALr093ikk5eYF1mUJ31EAJYBVl4gU6RmD7Dp0Iu1X1zwxB7JZYZCqUOmhyB1lf8oA994ChY_VkprCF_A0NcLpee8iW7d077OVODp14M4w7D6hPLJDa4T0GDjMH-o21b2n6YqoxbUuPPGAPCypb7e9zGliZWkpIyBXzvw8pwQ708iFc4AMZswlS8cYiS-6n3VrGosvT5UplUHdpPONfN_UYHOFwIWwErmxABUZbKNHWM0t1opDlysAIXm5lSOf7NFAVA05UQGofBty1N1rnSey6ElXk9lf3gdxKDfkgZVqKlTiuh54bm9L3Kgu6ZLKqTyxOWYiYW2T2G79tXyLAQDrl6FxRwlGpUWGhqsmN_MSImcSR3R7Y7uwsQshS6hg7zXJo4IQ3ok7-RvP1-bn9d9goAHPSYASnrWAG8IsIFRK2yJyAEIiUNL_tFQ3TulU3uEgJIECrqKn6jFcLQ_er4AnCEJy3Old1rXxZsMSLhHuucqhkByUT2iP5jsupSeTaCgRUKUMQwJ9iUeLAp4aAIZAertDuVVZli5fRrFByO6h7wZ6ewNkNen3vwFgDU3V1_xXIZCo_GFghO-oGMysxETIB-IvqRH0qLWNn0z771zagoT4Ri2HmQNRcKmA9uBpSpJ2nYIkMJ98CYm5kHvlgZgZp_YEffITAXZ9drxobjxrm4o73l9nhtDdPpY3D1ztv3l3kFX0K2OdpG5whWZ4kuEYmPuugT49EVQXS4Xdpo_aS6RNKwc7ffpbhl-ztL-H54o9-NIoveutL8V957RA",
					  "ciphertext": "V4iZyqGIdT83y_Eb6dE2c5l0-LMzKAXVnJwmXt9337d9haaaHlGYFUKvF3zvTZGBJ2PXLQEFWmqZ59lseWeSGA1TklJIWjQbb-1oCdE8607piGyFiGyjlsd5CEzfJuVZXmYQz3J4g6NIHlMGIoKTx6aa_A-qYkszxoKdlvnmwHLhm95vr9k9GNxWIblWK-rJkntpPTWecV7Y1nI2yb3nzJUBDfqDzfKb9YW2x--8KFs8n4RcSZr3d07RCB7QyxQKl9AFd5n5thTO4_UcRChvfc1aawFV4lnTHCGLRAwPo9P0JMNf3v51mfSstGwvRotRG2t9S3IWG4C_94VOeEVZPlclmt5uYJXPvQ4Fip4RHtwG1mRFRtTTzTblfqELzPe0VA"
					}
					""";
			var decrypted = JWE.parse(jwe).decrypt(alg);
			Assertions.assertEquals(EXPECTED_PAYLOAD_EN_DASH, decrypted.payload());
			Assertions.assertEquals(EXPECTED_AAD, decrypted.aad());
		}

	}

	@Nested
	@DisplayName("mode_psk")
	class PskMode {

		private static final Psk PSK = new Psk(new SecretKeySpec(new byte[32], "Generic"), "psk-1".getBytes(StandardCharsets.UTF_8));
		private static final Psk OTHER_KEY = new Psk(new SecretKeySpec(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}, "Generic"), "psk-1".getBytes(StandardCharsets.UTF_8));
		private static final Psk OTHER_ID = new Psk(new SecretKeySpec(new byte[32], "Generic"), "psk-2".getBytes(StandardCharsets.UTF_8));

		private KeyPair keyPair;

		@BeforeEach
		void setup() {
			keyPair = Curve.P256.generateKeyPair();
		}

		@Test
		@DisplayName("round-trips with a PSK and carries psk_id in the protected header")
		void testRoundTrip() throws JoseException {
			var jwe = JWE.build("payload").encrypt(Alg.hpke0(keyPair.getPublic()).withPsk(PSK)).toCompactSerialization();
			var parsed = JWE.parse(jwe);
			Assertions.assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString("psk-1".getBytes(StandardCharsets.UTF_8)), parsed.parsedProtectedHeader().get("psk_id").getAsString());
			Assertions.assertEquals("payload", parsed.decrypt(Alg.hpke0(keyPair.getPrivate()).withPsk(PSK)).payload());
			// psk_id may be listed in crit and is understood without declaring it
			var critJwe = JWE.build("payload").withProtectedHeader(JsonParser.parseString("{\"crit\":[\"psk_id\"]}").getAsJsonObject()).encrypt(Alg.hpke9(JWK.parsePublic(Hpke9.PRIVATE_JWK)).withPsk(PSK)).toCompactSerialization();
			Assertions.assertEquals("payload", JWE.parse(critJwe).decrypt(Alg.hpke9(JWK.parsePrivate(Hpke9.PRIVATE_JWK)).withPsk(PSK)).payload());
		}

		@Test
		@DisplayName("the token's mode must match the configured PSK, and the PSK must match")
		void testModeAndPskMismatch() throws JoseException {
			var withPsk = JWE.parse(JWE.build("payload").encrypt(Alg.hpke0(keyPair.getPublic()).withPsk(PSK)).toCompactSerialization());
			var withoutPsk = JWE.parse(JWE.build("payload").encrypt(Alg.hpke0(keyPair.getPublic())).toCompactSerialization());

			assertDecryptFails(withPsk, Alg.hpke0(keyPair.getPrivate()), "no PSK is configured");
			assertDecryptFails(withoutPsk, Alg.hpke0(keyPair.getPrivate()).withPsk(PSK), "mode_base");
			assertDecryptFails(withPsk, Alg.hpke0(keyPair.getPrivate()).withPsk(OTHER_ID), "does not name the configured PSK");
			assertDecryptFails(withPsk, Alg.hpke0(keyPair.getPrivate()).withPsk(OTHER_KEY), "Failed to open");
		}

		@Test
		@DisplayName("psk_id must not be supplied by the caller and must be in the protected header")
		void testPskIdPlacement() throws JoseException {
			var alg = Alg.hpke0(keyPair.getPublic()).withPsk(PSK);
			Assertions.assertThrows(IllegalArgumentException.class, () -> JWE.build("payload").withProtectedHeader(JsonParser.parseString("{\"psk_id\":\"x\"}").getAsJsonObject()).encrypt(alg));
			Assertions.assertThrows(IllegalArgumentException.class, () -> JWE.build("payload").withUnprotectedHeader(JsonParser.parseString("{\"psk_id\":\"x\"}").getAsJsonObject()).encrypt(alg));

			// a token whose psk_id sits in the unprotected header is refused before any decryption attempt
			var json = JsonParser.parseString(JWE.build("payload").encrypt(alg).toJsonSerialization()).getAsJsonObject();
			var protectedHeader = JWE.parse(json.toString()).parsedProtectedHeader();
			var pskId = protectedHeader.remove("psk_id");
			json.addProperty("protected", Base64.getUrlEncoder().withoutPadding().encodeToString(protectedHeader.toString().getBytes(StandardCharsets.UTF_8)));
			var unprotected = new JsonObject();
			unprotected.add("psk_id", pskId);
			json.add("unprotected", unprotected);
			assertDecryptFails(JWE.parse(json.toString()), Alg.hpke0(keyPair.getPrivate()).withPsk(PSK), "protected header");
		}

		private static void assertDecryptFails(org.cryptomator.jose.jwe.ParsedJWE parsed, DecryptionAlg alg, String expectedReason) {
			var thrown = Assertions.assertThrows(JoseDecryptException.class, () -> parsed.decrypt(alg));
			Assertions.assertEquals(1, thrown.getSuppressed().length);
			Assertions.assertTrue(thrown.getSuppressed()[0].getMessage().contains(expectedReason), thrown.getSuppressed()[0].getMessage());
		}

	}

}
