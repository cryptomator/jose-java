package org.cryptomator.jose.util;

import java.util.Base64;

/// Strict base64url (RFC 4648 Section 5, without padding), as required by [RFC 7515, Section 2](https://www.rfc-editor.org/rfc/rfc7515#section-2)
/// for every JOSE segment and header parameter. Unlike [Base64#getUrlDecoder()], this rejects `=` padding and non-canonical trailing bits, so every byte
/// sequence has exactly one accepted encoding: otherwise a token would have several distinct serializations that verify or decrypt identically, defeating
/// any caller-side cache, replay or revocation check keyed on the token string.
public final class Base64Url {

	private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
	private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

	private Base64Url() {
	}

	/// Encodes the given bytes as unpadded base64url.
	///
	/// @param bytes The bytes to encode
	/// @return The canonical base64url encoding
	public static String encode(byte[] bytes) {
		return ENCODER.encodeToString(bytes);
	}

	/// Decodes a canonical unpadded base64url string.
	///
	/// @param encoded The base64url string
	/// @return The decoded bytes
	/// @throws IllegalArgumentException if the input contains padding or characters outside the base64url alphabet, has an impossible length, or is not the canonical encoding of its value
	public static byte[] decode(String encoded) throws IllegalArgumentException {
		var decoded = DECODER.decode(encoded); // rejects characters outside the URL-safe alphabet and impossible lengths, but accepts padding and non-zero unused trailing bits
		if (!ENCODER.encodeToString(decoded).equals(encoded)) { // re-encoding exposes both
			throw new IllegalArgumentException(encoded.endsWith("=") ? "base64url must not be padded" : "Non-canonical base64url encoding");
		}
		return decoded;
	}

}
