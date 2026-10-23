package org.cryptomator.jose;

import com.google.gson.JsonObject;
import org.cryptomator.jose.jwe.EncryptedJWE;
import org.cryptomator.jose.jwe.SimpleEncryptedJWE;
import org.cryptomator.jose.jwe.SingleRecipientEncryptedJWE;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

public class APITest {

	@Nested
	@DisplayName("Test supported serialization formats")
	class SerializationFormats {

		private static final String TO_GENERAL_JSON = "toJsonSerialization";
		private static final String TO_FLATTENED_JSON = "toFlattenedJsonSerialization";
		private static final String TO_COMPACT = "toCompactSerialization";

		@BeforeEach
		public void setup() {
			Assertions.assertDoesNotThrow(() -> EncryptedJWE.class.getMethod(TO_GENERAL_JSON));
			Assertions.assertDoesNotThrow(() -> SingleRecipientEncryptedJWE.class.getMethod(TO_FLATTENED_JSON));
			Assertions.assertDoesNotThrow(() -> SimpleEncryptedJWE.class.getMethod(TO_COMPACT));
		}

		@Test
		@DisplayName("Only General JSON serialization allowed when having multiple recipients")
		public void testSerializationWithMultipleRecipients() {
			var withMultipleRecipients = JWE.build("payload").encrypt(Enc.A256GCM, Alg.pbes2("secret".toCharArray(), 1000), Alg.pbes2("secret".toCharArray(), 1000));

			Assertions.assertInstanceOf(EncryptedJWE.class, withMultipleRecipients);
			Assertions.assertDoesNotThrow(() -> EncryptedJWE.class.getMethod(TO_GENERAL_JSON));
			Assertions.assertThrows(NoSuchMethodException.class, () -> EncryptedJWE.class.getMethod(TO_FLATTENED_JSON));
			Assertions.assertThrows(NoSuchMethodException.class, () -> EncryptedJWE.class.getMethod(TO_COMPACT));
		}

		@Test
		@DisplayName("Only General or Flattened JSON serialization allowed when having AAD")
		public void testSerializationWithAadOrUnprotectedHeader() {
			var withAAD = JWE.build("payload").withAad("aad").encrypt(Enc.A256GCM, Alg.pbes2("secret".toCharArray(), 1000));

			Assertions.assertInstanceOf(SingleRecipientEncryptedJWE.class, withAAD);
			Assertions.assertDoesNotThrow(() -> SingleRecipientEncryptedJWE.class.getMethod(TO_GENERAL_JSON));
			Assertions.assertDoesNotThrow(() -> SingleRecipientEncryptedJWE.class.getMethod(TO_FLATTENED_JSON));
			Assertions.assertThrows(NoSuchMethodException.class, () -> SingleRecipientEncryptedJWE.class.getMethod(TO_COMPACT));
		}

		@Test
		@DisplayName("Only General or Flattened JSON serialization allowed when having Unprotected Header")
		public void testSerializationWithUnprotectedHeader() {
			var obj = new JsonObject();
			obj.addProperty("foo", "bar");
			var withUnprotectedHeader = JWE.build("payload").withUnprotectedHeader(obj).encrypt(Enc.A256GCM, Alg.pbes2("secret".toCharArray(), 1000));

			Assertions.assertInstanceOf(SingleRecipientEncryptedJWE.class, withUnprotectedHeader);
			Assertions.assertDoesNotThrow(() -> SingleRecipientEncryptedJWE.class.getMethod(TO_GENERAL_JSON));
			Assertions.assertDoesNotThrow(() -> SingleRecipientEncryptedJWE.class.getMethod(TO_FLATTENED_JSON));
			Assertions.assertThrows(NoSuchMethodException.class, () -> SingleRecipientEncryptedJWE.class.getMethod(TO_COMPACT));
		}

		@Test
		@DisplayName("Recipient overloads preserve the type-state of the alg overloads")
		public void testRecipientOverloads() {
			var recipient = Recipient.withAlg(Alg.pbes2("secret".toCharArray(), 1000)).withClaim("kid", "kid");

			Assertions.assertInstanceOf(SimpleEncryptedJWE.class, JWE.build("payload").encrypt(Enc.A256GCM, recipient));
			Assertions.assertInstanceOf(SingleRecipientEncryptedJWE.class, JWE.build("payload").withAad("aad").encrypt(Enc.A256GCM, recipient));
			EncryptedJWE multi = JWE.build("payload").encrypt(Enc.A256GCM, recipient, recipient); // static type: General JSON only (the runtime type implements everything)
			Assertions.assertDoesNotThrow(multi::toJsonSerialization);
		}

		@Test
		@DisplayName("All serialization formats allowed for single recipient and no AAD or unprotected header")
		public void testSerializationWithSimpleJwe() {
			var simpleJwe = JWE.build("payload").encrypt(Enc.A256GCM, Alg.pbes2("secret".toCharArray(), 1000));

			Assertions.assertInstanceOf(SimpleEncryptedJWE.class, simpleJwe);
			Assertions.assertDoesNotThrow(() -> SimpleEncryptedJWE.class.getMethod(TO_GENERAL_JSON));
			Assertions.assertDoesNotThrow(() -> SimpleEncryptedJWE.class.getMethod(TO_FLATTENED_JSON));
			Assertions.assertDoesNotThrow(() -> SimpleEncryptedJWE.class.getMethod(TO_COMPACT));
		}

	}

}
