package org.cryptomator.jose;

import org.cryptomator.jose.alg.HmacAlg;

import javax.crypto.SecretKey;

/// A JWS algorithm using a MAC, identified by its `alg` header value ([RFC 7518, Section 3.2](https://www.rfc-editor.org/rfc/rfc7518#section-3.2)).
/// The same key signs and verifies, so one instance serves both directions. Independent of the JWE [Alg] hierarchy.
public sealed interface MacAlg permits HmacAlg {

	/// @return The `alg` (algorithm) header parameter value identifying this algorithm
	String name();

	/// @param signingInput The JWS Signing Input, i.e. `ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload))`
	/// @return The JWS Signature
	byte[] sign(byte[] signingInput);

	/// @param key The HMAC key, at least 256 bits long, which remains owned (and eventually destroyed) by the caller
	/// @return `HS256` (HMAC using SHA-256)
	/// @throws IllegalArgumentException if the key is shorter than the hash output
	static MacAlg hs256(SecretKey key) {
		return new HmacAlg(HmacAlg.Type.HS256, key);
	}

	/// @param key The HMAC key, at least 384 bits long, which remains owned (and eventually destroyed) by the caller
	/// @return `HS384` (HMAC using SHA-384)
	/// @throws IllegalArgumentException if the key is shorter than the hash output
	static MacAlg hs384(SecretKey key) {
		return new HmacAlg(HmacAlg.Type.HS384, key);
	}

	/// @param key The HMAC key, at least 512 bits long, which remains owned (and eventually destroyed) by the caller
	/// @return `HS512` (HMAC using SHA-512)
	/// @throws IllegalArgumentException if the key is shorter than the hash output
	static MacAlg hs512(SecretKey key) {
		return new HmacAlg(HmacAlg.Type.HS512, key);
	}

}
