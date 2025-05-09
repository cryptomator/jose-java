package org.cryptomator.jose.parser;

import com.google.gson.JsonObject;

/// @param payload           The plaintext content of the JWE
/// @param protectedHeader   BASE64URL(UTF8(JWE Protected Header))
/// @param unprotectedHeader JWE Shared Unprotected Header
/// @param aad               BASE64URL(JWE AAD)
public record DecryptedJWE(String payload, JsonObject protectedHeader, JsonObject unprotectedHeader, String aad) {

}
