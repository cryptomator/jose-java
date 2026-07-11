package org.cryptomator.jose.alg;

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

		private static final String PRIVATE_JWK = """
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
			var privateKey = (ECPrivateKey) JWK.parse(PRIVATE_JWK);
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

		private static final String PRIVATE_JWK = """
				{
				  "kty": "AKP",
				  "alg": "HPKE-9",
				  "kid": "BeWp7Y5tolX2sSYMKIaG6WUVE-arTKcS2Ok8EgqFqrE",
				  "priv": "tQDSUt-Mgd0LNFiUK9VEluJnrtg057pCq97A54EdbiM"
				}
				""";

		private DecryptionAlg alg;

		@BeforeEach
		void setup() throws JoseParseException {
			this.alg = Alg.hpke9((PrivateKey) JWK.parse(PRIVATE_JWK));
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

}
