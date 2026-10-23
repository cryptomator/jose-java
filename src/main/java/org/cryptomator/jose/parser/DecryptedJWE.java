package org.cryptomator.jose.parser;

import com.google.gson.JsonObject;

/// A successfully decrypted JWE. The payload, the protected header and the AAD are authenticated; the unprotected header is not.
///
/// @param payload           The plaintext content of the JWE
/// @param protectedHeader   The JWE Protected Header (authenticated)
/// @param unprotectedHeader The JWE Shared Unprotected Header merged with the decrypting recipient's per-recipient header (NOT authenticated)
/// @param aad               BASE64URL(JWE AAD) (authenticated)
public record DecryptedJWE(String payload, JsonObject protectedHeader, JsonObject unprotectedHeader, String aad) {

	@Override
	public String toString() {
		// keep the plaintext (for this library's main use: key material) out of logs, assertion messages and debugger views
		return "DecryptedJWE[payload=<redacted>, protectedHeader=" + protectedHeader + ", unprotectedHeader=" + unprotectedHeader + ", aad=" + aad + "]";
	}

}
