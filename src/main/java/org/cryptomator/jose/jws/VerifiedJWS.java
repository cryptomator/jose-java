package org.cryptomator.jose.jws;

import com.google.gson.JsonObject;

/// A JWS whose signature has been verified.
///
/// @param payload The JWS Payload
/// @param protectedHeader The JWS Protected Header
public record VerifiedJWS(String payload, JsonObject protectedHeader) {

}
