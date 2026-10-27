package org.cryptomator.jose.alg;

import java.nio.charset.StandardCharsets;

import java.util.Base64;

import java.security.GeneralSecurityException;

import java.security.KeyPairGenerator;

import java.security.KeyPair;

import javax.crypto.spec.SecretKeySpec;

import org.cryptomator.jose.hpke.XwingProvider;

import org.cryptomator.jose.Recipient;

import org.cryptomator.jose.Psk;

import org.cryptomator.jose.JoseException;

import com.google.gson.JsonParser;
import org.cryptomator.jose.Alg;
import org.cryptomator.jose.DecryptionAlg;
import org.cryptomator.jose.Enc;
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
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;

class HPKEKeyEncryptionAlgTest {

	// the same Fellowship quote, but the two drafts differ in their choice of dash
	private static final String EXPECTED_PAYLOAD_HYPHEN = "You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";
	private static final String EXPECTED_PAYLOAD_EN_DASH = "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";
	private static final String EXPECTED_AAD = "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc"; // "The Fellowship of the Ring"

	/// test vectors from [draft-ietf-jose-hpke-encrypt, Appendix A.2](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt-22#appendix-A.2)
	@Nested
	@DisplayName("HPKE-0-KE test vectors")
	class Hpke0Ke {

		private static final String PRIVATE_JWK = """
				{
				  "kty": "EC",
				  "crv": "P-256",
				  "x": "erH26InyPQifTIwmyKs63u4SUzglAHXNm2ZWT2LQ-rM",
				  "y": "GTGOC0_TnYc_Cm4dsgY8qdixil7AObs5-Xtk0QJeoH8",
				  "d": "MzJOwOcw1LDGZ-Ia6Zz5ay9zWUZKIhXkBcfq0dPA5Do",
				  "alg": "HPKE-0-KE",
				  "use": "enc",
				  "kid": "23i_7tQXiLxih47kQtE2yHy7d8q253Kp9R9i6aDyHng"
				}
				""";

		private DecryptionAlg alg;

		@BeforeEach
		void setup() throws JoseParseException {
			var privateKey = (ECPrivateKey) JWK.parsePrivate(PRIVATE_JWK).privateKey();
			this.alg = new HPKEKeyEncryptionAlg(HPKE.hpke0(), null, privateKey);
		}

		@Test
		@DisplayName("decrypt compact serialization")
		void decryptCompact() throws JoseParseException, JoseDecryptException {
			var jwe = """
					eyJhbGciOiJIUEtFLTAtS0UiLCJraWQiOiIyM2lfN3RRWGlMeGloNDdrUXRFMnlIeTdkOHEyNTNLcDlSOWk2YUR5SG5nIiwi\
					ZW5jIjoiQTEyOEdDTSIsImVrIjoiQk4xRWI1bVFCZTgyLVRpWTJYc0xjWEhmb3ZjNWFxajRIRW5Ick10aFFoMDhqUDl5Vjd2\
					U3VBZjZuYjNLQ3pSUWJmbHlGV2k3bDlrR3BtTm1xaTNYaW1RIn0.lnz6tY7OMgEqr2dUBFLhbRV5SV5NnnE75YoGf8fdCdQ.\
					B01l-CsTkWGSh-8o.n33IRmokhNrqtaG5AL9COw-bVmYiPqCLBgludwQF3hyMYuagt4xxbKA2YdLHzgYk4ZCZQRdK5UJJcIK\
					UsBsWNyDYhS0oZVcxq3wXOeG6jkEqUCzTU3PS0JeLW8uihm9gSjlW42dKUiYjqXL8kIJuWbCxqYs-Dslm5hfx4u_a06hvIRv\
					JjVVQ4eWZMtUo5nIumyyid9qKwFFo_BLXaSxRZ7sa4TSRpu1Qywl8t3HcnnKThFfCSc6jIcJ3O9GIFXMDKqzBiciaxjim3xf\
					v6A3qMHmIkF_rTT0dj9qmlolOfZeElX7sseq0EpOe9MPwcpFR3mZVUCe74FGUJNj4szJTb8pVgaZ9Yo5rXFKKn9s.MCd0fKM\
					DwsgD6MW2XKzWWg""";
			var decrypted = JWE.parse(jwe).decrypt(alg);
			Assertions.assertEquals(EXPECTED_PAYLOAD_HYPHEN, decrypted.payload());
		}

		@Test
		@DisplayName("decrypt flattened JSON serialization with AAD")
		void decryptFlattened() throws JoseParseException, JoseDecryptException {
			var jwe = """
					{
					  "protected": "eyJhbGciOiJIUEtFLTAtS0UiLCJraWQiOiIyM2lfN3RRWGlMeGloNDdrUXRFMnlIeTdkOHEyNTNLcDlSOWk2YUR5SG5nIiwiZW5jIjoiQTEyOEdDTSIsImVrIjoiQkNlSmd0RGZGeVdtTDlJek0yT1Vnd1owWm9tWHVhb3BEcW5fR0JYX2V4N0pENlRyWWpLOUI5R2ZRYWhIamRuTGlsQ2V6WlNSX2NvaUtnVC1IQVhnSlFNIn0",
					  "aad": "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc",
					  "iv": "hsc8LLwbgwf33MdT",
					  "ciphertext": "vwkACubXsG6xfuEbeZW24DJWq-ZlRExN1uaTyfwaNoCwDaURkrC0Vkc5w9B_KntgOMYvOgAVfSkqkztcRFX-AKIaOKGKYvPAY9ujuQtyA7SFMvaOjmao2XD96LtoeexaYrganCxHvJhjgyRH8xpb_QYVUGdmpjj9r_uNqZVTAuuUlrE87LbGkNaQuHpRCpYG7JbYHp8Sovnbepy84ORGXkhg7KamMfQQQ_ob5C5aY0g2BBqRgyuNErzDCq3RVVo91ddpGbSys25jlvAbqziBW1YOLIoLoGJDdqbykKzjravg1R1g7QCOpdN0ozcE_oEEHFEyRTilYRkxH_CqV2hxhakqDpGj3Q9qHGigJEk",
					  "tag": "Afab-bCOAfBSYJgIsaxxZQ",
					  "encrypted_key": "-mXiAU7aot-kdZ8KhWDoM_jXHk6_B5g0vH77u6r49os"
					}
					""";
			var decrypted = JWE.parse(jwe).decrypt(alg);
			Assertions.assertEquals(EXPECTED_PAYLOAD_HYPHEN, decrypted.payload());
			Assertions.assertEquals(EXPECTED_AAD, decrypted.aad());
		}

	}

	/// test vectors from [draft-ietf-jose-hpke-pq-pqt, Appendix A.4](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-pq-pqt-01#appendix-A.4)
	@Nested
	@DisplayName("HPKE-9-KE test vectors")
	class Hpke9Ke {

		// AKP JWK (RFC 9964) from the test vector: "pub" is the X-Wing public key, "priv" the 32-byte seed
		private static final String PRIVATE_JWK = """
				{
				  "kty": "AKP",
				  "alg": "HPKE-9-KE",
				  "kid": "I8THo1KoAq9OG96cJTyk2WF8abZqb3kKKHgdfajHUb8",
				  "pub": "8rGsDcYDVYgHXJdoG_y4snlf_zZ2J7IJ_dyGafoU-8PBqdSb4dKAAggLvU\
				LOi_kwqxCdLXqh7sinPlUPEQAXeaITnOkYJhCJN_tpWBBbZclC4sAXNHItUAV4Kf\
				AmEgyll0KiqKRohYQjhwSlSAQhA9NwAPJhYMgZPWkDf1zFJexT_prKclLGRzU-Ak\
				uACumcboErJqGYIRdXVfN7JqfIXfcNI_QCSpcpuAk_wMOWxOIj2WxdCMMfd1QBFK\
				oAi1cM-_cuL1JWwOK5SsC7FKg5YJZdZPJ53RkFUusZPrhcWsZMsOFXJmgOjeV9bU\
				WA1npKEJt7nDeU9EGbICVel-RChriHe1tcx4OFgUCrCBvEpJl9d0am5jqwYQB-Wm\
				wVZ3IFVHM2c5NCb_MHhknJsaCqrSMmEUJ7XBpTWbdUlMNMMiq9Pcd2WwvMyoZmNa\
				c_xKmk5VxkBqorWUZ3ieVwcGYt7cZO2mvJwilCccsz6TTIZnuymJU57-J510EbVf\
				GXSBN3_BCpfwHAAqV-rZab5oWPFeYQikjAHieblCgN7bSKl6U-NCpoaPA-n1Q3jM\
				Y-vzFy4iaM8ThfoXdzXQo0oLCvyOZ4aqlv4EqYQRFh51RN6Jkyk5eqUUaHmaAV_y\
				yj7wBEkZNIDWNOy7ZAunaDl5tXFpUaPmHLQ4RQV1fCA8Y27gQ_4nOY2zdHhnq12W\
				OrvNN-DrdGI0ShpNWzARMtM6yiDXUV2yR_b6KTDyq0YyMzQCHBQhscrXCN2QxXd4\
				hHj-gjZzoJlim6XybGlrG6EaMkvIKfwuhZ7oxRTuC3hGJBSkMptQNg3Th4luol-F\
				l7WepM0vOYOVyYdRANeszJ6WTKZJCtzUhPcSBzeImXaDqNeCAt9jIBXpoJX6m8RV\
				iM4bW8YgtR6vK2ceNW5yWCAfOA9NmiBDAhFaMNTnueistr2eEJhzFZ2wJsT1MG-v\
				G2EIyuUNBqwlNjVvR4vfEAWOmeBuA5v7By3ycsOMFv2hk2eGssIzmE86ZOj5Oj11\
				QWFPRrSMx5zLdDu0ep_pPCYNUicStcDtIvy-pfJ2uEdBoJ5hdE9duIGZOlTeozIW\
				deEcBrv-sEJmKk7hNeOSBpVpAlYDTDTVpvOik-mJAR_hbNnfCY55sFD7C-zxOfrj\
				QdYwWLDSSH5mV4IQKzseJ8x1w5cbWWzbUqF2pNZBDEAjSpiqqVxgOAikaOwzMaWA\
				ERNOeX6NFYkmga2nREl5t46woTvbqBTSxBMOxcS3KCbzmTcqrLVfS9Cci5DaAdUj\
				ad8NzMQBoHywWIAFTA8Bl4p8cb7GqR9FcJYVsM6QlcjcGCZ5KhahgYOlBH5lw6bR\
				Mi48JzHrRWa1otXxmXprcLF4QiBKEZfKpHrSsszlCAKOKytlG7_xtNPRZ_UeZmeT\
				RiyHWVDCcQSzM2W9U_7hfGa-BErmW20CNBitqWZmEkmGRci2KxP7cJceuTXjpYAc\
				VWm1x4ZVN1_JtCisCU5egDoXIi8uFHwZigKhcBUBIS-AepvSKNdCA3HqeWzydKaR\
				zM6Hd1iEyiOQZdz4pcGDrkcsbOgiUpCHGM_OPeIAPlZ8DqRjh6Wxa8O8YwyrfJZs\
				6vLUcAjW-Jn5AaNpQFWU_VdbhTDQ",
				  "priv": "q_aDEMZpRAjbiqHwO23vKcgImYieSqUsCK7wWZEsq8Y"
				}
				""";

		private JWK.Private jwk;
		private DecryptionAlg alg;

		@BeforeEach
		void setup() throws JoseParseException {
			this.jwk = JWK.parsePrivate(PRIVATE_JWK);
			this.alg = Alg.hpke9Ke(jwk);
		}

		@Test
		@DisplayName("encrypt with the public JWK, decrypt with the private JWK")
		void roundTrip() throws JoseParseException, JoseDecryptException {
			var publicJwk = JsonParser.parseString(PRIVATE_JWK).getAsJsonObject();
			publicJwk.remove("priv"); // a JWK without private material parses as JWK.Public
			var publicKey = JWK.parsePublic(publicJwk);
			Assertions.assertEquals(jwk.toPublic(), publicKey);

			var jwe = JWE.build(EXPECTED_PAYLOAD_EN_DASH).encrypt(Enc.A256GCM, Alg.hpke9Ke(publicKey)).toCompactSerialization();
			var decrypted = JWE.parse(jwe).decrypt(alg); // succeeds only if "pub" is the public key belonging to the "priv" seed

			Assertions.assertEquals(EXPECTED_PAYLOAD_EN_DASH, decrypted.payload());
			Assertions.assertEquals("HPKE-9-KE", decrypted.protectedHeader().get("alg").getAsString());
			Assertions.assertEquals("A256GCM", decrypted.protectedHeader().get("enc").getAsString());
			Assertions.assertTrue(decrypted.protectedHeader().has("ek"));
		}

		@Test
		@DisplayName("decrypt compact serialization")
		void decryptCompact() throws JoseParseException, JoseDecryptException {
			var jwe = """
					eyJhbGciOiJIUEtFLTktS0UiLCJraWQiOiJJOFRIbzFLb0FxOU9HOTZjSlR5azJXRjhhYlpxYjNrS0tIZ2RmYWpIVWI4Iiwi\
					ZW5jIjoiQTI1NkdDTSIsImVrIjoiQkxWb1lHUWROenpXUV9zTjVfeVZWOGpWajVqb0ZVSWdRVDBwV3h0ZlRwLWgxUk91azZZ\
					YVN1OXlaR3gtaTg4TW1sY0EwTlVMUHZEVEZCX3otZUJ5dHlubnVfZnB0d0ptaW5JVlcydWdxQ1hVOTBUQXJ5Z3RWLVJkY1ZJ\
					NnhkRGFLRTJjTmx5WVRIVHF4Z1VHb0ZSNVEyMEVJM0dSazVSdGh5REx5cTZRdUdVMHk4RlM4NFB6OHVCY0VPTnRtZWJ4cW4w\
					UHIyWmFJNld0VW1IdzY2SXJWLW9ZXzRBWk5tazZmOUxld19iVWtFU25oRHBzbWVYbUpvcy1DbmlQZ1I4SDZYZWlfRHFTcFpq\
					X1BGRTBmVVBDNW91QW1zZ2hRQ2pNNm4tUnhtbDVJd2xaakgweW9qby0zYkQ0SkxEazZUV3Z3UUF2Qkp0Z2dUMFh0dTZJcTVT\
					aDY0TGprZHZTeXZscHZHckctbzNCNXdHYWh3X0JpVDg1aHVWOFRadkU1N3FSdy1FOEJqbWpoNHY1eDZVNG1KdnNpQW1KS3NC\
					NUxRdno0QkRkU0o1d3Jqcm9EWlNYV0stVGI5UjJ6MERKTjZDTThvX3dMRnQwcGMzajZCWjZKOVFIcE5UM0ZUV2NEVFQ5b0lK\
					SHBUQjgyUXpraDN0LVowSW01ckc5OUR0OGZVY1hXWHVkOWFTV3JUekw2S0RVakU2bENmTnVTRHJNd3JNSE9Nakp2QU5sS0ph\
					YzRkbUgtMXR4RTdOZUpBWkFnNE1ldVlQQ1NFeVNKMUpvcHZtRF9HOGdINUlKc0RIU0ZYVWUybGhCUkF1djNlQmtsY25sSUpR\
					Q3VKc1BGSmVRVkNYU0xMWFBjcDlRakVXemFGSmc0VDlzak5BLXZNZ0dQZVpYcUpuQzRMcnhPZkVaSHpSTXJoaGw1WFdWeFJ6\
					a2dZLU1aOVhyclV5dHVnRGptay1UUVZzNjdyWjBTY3lNUXpaVWpmWU04Q3ZJWHUxUW9zc1ozNlNHN3ZlYTh2Tkt1Rmw4WFhP\
					d1RFcW10Qlh3Y3puYnZLcHBqaWU3NE9RUndJSW4yUVBIRWlEbzU1azJpOWh3aHY1UzYxcHhQMk9Ga0NpTG9TUFU5N1NLckZZ\
					NDRPNEtSbXdkalp2WkJ6VllkUXBWWjdNY05nTGZoOHZpR2l5SzhObnJBQVItU1RXdTc3UGJNa3JMclZzTHE1bVJqT0o1S2Nw\
					bjV1aFdCR09EdkwyWkZ5akdFa09ERVpWcUVFLUpwYkc4d2d4Y0JBcTg3TUZfTVQtN1dqZ3RwRWR6NGxZU05QbTFaQklZUlVO\
					aGdYaTRrUmNhVkhyb2lvdmFTZVl1OUNDNnZNeXhJWTk2Yk5pMHRxTVdmQkR5dEJfWXI0TXpORHN4TmJmMzgtYVpBUnRodkZt\
					T3F3Z2xGZVNjSTZpMkI1OEJua011WUJjbXhzaWFXeHc3N3R3Q2M5Vk5CeHlRRk43aUFUcjkzbmFHNmNUTWlsQXp0aGpqZ3hh\
					VkQ3Z3BUb0Y5WFFMck5EdVdTWnNuOFZDV2J0dHU1dkhxb1ZaMkhTNDllVTEyLS1vS0xWWjY5eTRwOHo2cjU4S1BUSmo5dlpo\
					dXoyMWNubzFteW41azN5N210NDRTb2MydHRlZjdwQXBRLWZLMkxibGNBMlFNMTZXMllKdWhXTkdOMEprbURKb3VpQXEzS2xQ\
					NGZyVS1mNU8zdk5fLTdCS2ZYVGlpTGt6MzZMb19Jcllvd0FpdHBpSHJKSl9NcVFzX0xrRzJHZ1RFTWpNeEc4RG5MSlZPYXFz\
					dGttZWpFUWN3cTNOek11S2FkSmJqVlVLNlRncl83S1BTMmRXeFREZDFlelVPb0hxZVlrY2lRNEQ5N0RrZWZBRTNVQTM0QVUz\
					NVZNSEtpak9NM1ZaeURHd1gtUzA4VlVhbTJmMThrclQxNTMzQWVSZlkyXzVnWVktYVNhTVM2dGZXRkU4MGRNVUNybXdfeTlT\
					OE1nIn0.m33rDckJMAweQB0e1C7cc17C52_oNyzEtnoz5VZ1cLxEAMdx5YD-AP7wLeg6b4aQ.l3pLYmere0K8G8AF.k6oT3m\
					_ISW8okLHfAjFYBlTtMpB2rO7mRgkjHRSz-uGHo1naLCfzcQlgDKm4n5XmvUnxJ09Z5Xq877G2omHaAnJXWjA5r1zv7_rB7R\
					grkkU4EMPPfRYlRqlfReYGEv5rH2V0SUHMmVABgH1NbmMtWm2ccwyKtbZEgxMru79aDKbZ8MV_Zkt3hGJWVcQRYljGL-MM2g\
					qWpKn8Q73FT5CX4HsiLI0zn_b5j4qDXqsZGz_A66wndg5vcSRyt6F08bfvQ5hptrfdftUeMKn1z7PxI2T3Ye7AI34EIQdIJa\
					lrmGMUdzNU9xvLdwWD3N6Cy0HFEoWvFNpXVxxcDV2ybCRGsNzP-RlNhOeD56l-6Pf_mG7v.77mxN7ZlNwLuUio3mcxoxA""";
			var decrypted = JWE.parse(jwe).decrypt(alg);
			Assertions.assertEquals(EXPECTED_PAYLOAD_EN_DASH, decrypted.payload());
		}

		@Test
		@DisplayName("decrypt flattened JSON serialization with AAD")
		void decryptFlattened() throws JoseParseException, JoseDecryptException {
			var jwe = """
					{
					  "protected": "eyJhbGciOiJIUEtFLTktS0UiLCJraWQiOiJJOFRIbzFLb0FxOU9HOTZjSlR5azJXRjhhYlpxYjNrS0tIZ2RmYWpIVWI4IiwiZW5jIjoiQTI1NkdDTSIsImVrIjoiVHd6VWlPTlprbjNvSEl3RU1BX3FXbUtRU1UzNndNOEl6NUItMzFzdEp1dV9BV3lfTDFSU0xxQkZtQmNlOEotY25hUVhSczk0eVRIT1d2Z1hDMlVuektZdUQyay0wOERaU2xUb05nZldPaWl6UEV3a2FRQ2dEcFZlZkh2NklTWkctbzRoS3ZrZ2ZmVkxiQTNjdUhNOW14d1VKdTJGUWdLVjU2TUhQZzJIbDBLQm9ydXlQMGU4SUg3SW45RDV5V2R1WjR6SDJjM1lac3hnSXZMSzY1SU9nSVNvbDFEOHZ2M1k2YnptS0tUQlI1MHZrZ3oyZ3JESVNTMjE5Yl9qM01FRWFXeWdZNFNxQ2x1S2lzN2lkWll1SzM0d0FiYm1MT0tUWGhVNmxGajV1Nml3eTJLX1MweFJVS29kZmlzU24zOC1hRlREcEtSVEN4Wk55WFNSYWNHOXBMNnE2Q3h6UGZ4U2hHSXpjT2JTYm9oREdTdklnRHAybW1POFV1RGNfU18tR1lDN2tyaEpZNk9YRDBsNzR1OE5KQ2lOVGU3LXhPWlNnZVoyNVBiWm9FZXc5b0VINVhFZy0tV3MyZE5uTEpvdEFQaXN2NkNDZVVXQjFESENVUXpqSnNZTThfaFpKZ0R3RmZydzExOEZwaWJVOFlDd1lNUEF4THpzcTJjLTN0MG00ZnJEcFN0RWNnVHRSM2FnaFlyYW5zTHJmcmxKUkIzTmZpcmpnMFRYdjBEV1ZzM18wRUdqNDNDOWdGMWRiSXFyTmVpYlBVTGRCRVdZNjR2Uk1IOWJBSGlzTDE0NlQ1RlBuWTRiTzFhTldCNU9tZXJ6OXBGb2Fhcm9McDl0a1k1Z0NqREhvdmNORUFqNnBNVHhFa2tJMDhSRHlJSkdqRHc2Yi1ObGZsQldpSEZTQjdtZzJ0RUVuZGhjNmFRcmJkU2dUQ3liSnVfV0xBUDlQcEVoeDlqUG9vWm5tVGdXVWtVNHdtUXd0WHk4RzhVc3pMbXduWHpwck5mZF9JRVg5b1ZQQml5VDFZejFoQnJhMnVpWFZQWXM4ZGdlUWdKYnJIaWVzVnRzNlpuMGxIOVl3c2J3QjZTNGlkd2J0UWZEVTliVU4tUzNrRWZnWkJZVEFBS1Z0eS1Eam1tMEZrTTktTW9zUVNyNjVOM1NueEtoYVVNbHU0U3VPUG53bVMzVXRaMDZFQXZXSWQtNEozRkY0Z3B0RXR4czMxY3JEOF90eG9ydGpnR2FUV0o5dmdrZTMxeC1VUmlGb2hobUlMSmtHYjJ2UC04dmYxOHhOWGZmR20xeHZDR2dESXJya0V4YXJRSlBDLVdRbzdhaVcxNkRpc1JfZHQzRGVGeEdZTUt6S0ZGLUJmYWJ6bGFNRE5aMjhTeTdzUkRPbllpQklkODNRS2FGSXNKZjMxOEZvV0JqSVRqUmtjbnRPNXBsM0FpRUNFTVhfUU9tRXVOamdLaXNlNmZIYW1XYkZoOUhRdEZUZFJmRE5QMWxxUTFpSnpTSmhIMlVkMC1VMGFoZ2drMFdOLTZpWnhDSy1oOHQ5WlY2UFMtV0oxU3ZDeTkzaHBqWEV6LVA0RTV5VHhlSFd6ZVB5eUxWQzhqazFxOGZhc3FqRC1HZC1tMW9peDdIOHpOX19GblB0UTNrNFdWeEs2N1hsX0NpRTJnZjRsZ2FFclZCMDI0czI0SUtZRjVwNEZZdTluaGEwVDJuMkVTMU11RmR4Zk9pajdMN3dORGxLSjdXWTBUNnUzdGtMdnBKWTBxNS12NldQYk55dVBlbHdrcGxlZlJocFkxNk5UY2RacGozSlVSU0VWN3pjNzlLTTNkNmR6QzNEb3FZMWNlUlhSVUluRDZmY1lDVHRXUVRqd1dXRjVib25uVWIzcktzeTRxcDBqRHZuR2NPRG9NVVhkcm81Uzd4WWJ6di1aSTIyTzBWS1NDbGE1N3VzV0VqQzNxM2JvUHNobm90emE1X042clFuOVQxOWJSWVF3In0",
					  "aad": "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc",
					  "iv": "d8CFuwBEVbiI_nK7",
					  "ciphertext": "kmsiEt2hnihtuOyfGiFAs26cHoVya0vXhz62N6vmF4NnZP879ES3YkengaFdFYG3l16-N7GVar6OR0h-atBeDoMeGNv7QHLE9Pky5arS4kaL4y7j9BcffzA1Lq-Hx0cQzgvWu7c9xkOXDb6zS0liTxV6-ZMFHHdHdAd5ErMvQNtUwh8rvG1APw6QMrzb3SGUsmlTWE4-IMgq4KRKKNHHsdztLynzDcskM0yyASkO0giKYcp85uzZ3WYwnm5LOOen06Fi1Kj-U9Hd0JmIVsy58mNnCZSeEfLdIGyP3HvLqj4ngp_OvNuBKEp12OBbouXpJ4xuPla9FdgLoF3Foiw2GRhoqtYWSYuu4oRgmlXYOuSB",
					  "tag": "l7BtLt_8bQpsUK0NS-G5Gg",
					  "encrypted_key": "hEaoX4fNiWQ-xb_y31sERZsttys1fGKexhdYll0PkJDtNclb-M9rmeB7xQypVLaM"
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

		private static final Psk PSK = new Psk(new SecretKeySpec(new byte[64], "Generic"), "psk-1".getBytes(StandardCharsets.UTF_8));
		private static final Psk OTHER_ID = new Psk(new SecretKeySpec(new byte[64], "Generic"), "psk-2".getBytes(StandardCharsets.UTF_8));

		private KeyPair keyPair;

		@BeforeEach
		void setup() throws GeneralSecurityException {
			keyPair = KeyPairGenerator.getInstance("X-Wing", XwingProvider.INSTANCE).generateKeyPair();
		}

		@Test
		@DisplayName("round-trips with a PSK in compact and JSON serialization; psk_id is a per-recipient parameter")
		void testRoundTrip() throws JoseException {
			var encrypter = Alg.hpke9Ke(keyPair.getPublic()).withPsk(PSK);
			var decrypter = Alg.hpke9Ke(keyPair.getPrivate()).withPsk(PSK);
			var expectedPskId = Base64.getUrlEncoder().withoutPadding().encodeToString("psk-1".getBytes(StandardCharsets.UTF_8));

			var compact = JWE.build("payload").encrypt(Enc.A256GCM, encrypter).toCompactSerialization();
			Assertions.assertEquals(expectedPskId, JWE.parse(compact).parsedProtectedHeader().get("psk_id").getAsString()); // folded into the protected header
			Assertions.assertEquals("payload", JWE.parse(compact).decrypt(decrypter).payload());

			var json = JWE.build("payload").encrypt(Enc.A256GCM, encrypter, Alg.hpke9Ke(keyPair.getPublic())).toJsonSerialization(); // one PSK and one base recipient
			var parsed = JWE.parse(json);
			Assertions.assertEquals(expectedPskId, parsed.recipientHeaders().get(0).get("psk_id").getAsString());
			Assertions.assertFalse(parsed.recipientHeaders().get(1).has("psk_id"));
			Assertions.assertEquals("payload", parsed.decrypt(decrypter).payload());
			Assertions.assertEquals("payload", parsed.decrypt(Alg.hpke9Ke(keyPair.getPrivate())).payload()); // the base recipient is still decryptable without a PSK
		}

		@Test
		@DisplayName("a recipient's mode must match the configured PSK, which must match too")
		void testModeAndPskMismatch() throws JoseException {
			var withPsk = JWE.parse(JWE.build("payload").encrypt(Enc.A256GCM, Alg.hpke9Ke(keyPair.getPublic()).withPsk(PSK)).toCompactSerialization());
			var withoutPsk = JWE.parse(JWE.build("payload").encrypt(Enc.A256GCM, Alg.hpke9Ke(keyPair.getPublic())).toCompactSerialization());

			assertDecryptFails(withPsk, Alg.hpke9Ke(keyPair.getPrivate()), "no PSK is configured");
			assertDecryptFails(withoutPsk, Alg.hpke9Ke(keyPair.getPrivate()).withPsk(PSK), "mode_base");
			assertDecryptFails(withPsk, Alg.hpke9Ke(keyPair.getPrivate()).withPsk(OTHER_ID), "does not name the configured PSK");
			assertDecryptFails(withPsk, Alg.hpke9Ke(keyPair.getPrivate()).withPsk(new Psk(new SecretKeySpec(new byte[]{1}, "Generic"), "psk-1".getBytes(StandardCharsets.UTF_8))), "Failed to decrypt CEK");
		}

		@Test
		@DisplayName("psk_id is an alg-generated parameter and therefore refused as a caller claim")
		void testGeneratedParam() {
			var alg = Alg.hpke9Ke(keyPair.getPublic()).withPsk(PSK);
			Assertions.assertEquals(java.util.Set.of("alg", "ek", "psk_id"), alg.generatedHeaderParams());
			Assertions.assertThrows(IllegalArgumentException.class, () -> Recipient.withAlg(alg).withClaim("psk_id", "x"));
			Assertions.assertDoesNotThrow(() -> Recipient.withAlg(Alg.hpke9Ke(keyPair.getPublic())).withClaim("psk_id", "x"), "without a PSK it is an ordinary (if ill-advised) claim");
		}

		private static void assertDecryptFails(org.cryptomator.jose.jwe.ParsedJWE parsed, DecryptionAlg alg, String expectedReason) {
			var thrown = Assertions.assertThrows(JoseDecryptException.class, () -> parsed.decrypt(alg));
			Assertions.assertEquals(1, thrown.getSuppressed().length);
			Assertions.assertTrue(thrown.getSuppressed()[0].getMessage().contains(expectedReason), thrown.getSuppressed()[0].getMessage());
		}

	}

}
