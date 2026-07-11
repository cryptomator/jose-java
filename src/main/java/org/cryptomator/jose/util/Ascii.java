package org.cryptomator.jose.util;

import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/// Strict US-ASCII encoding. Unlike [String#getBytes], this rejects non-ASCII input instead of silently substituting `'?'`,
/// so the result is a faithful, injective image of the string — required where the bytes are authenticated (e.g. AEAD additional authenticated data).
public final class Ascii {

	private Ascii() {
	}

	/// Encodes the given string as US-ASCII bytes.
	///
	/// @param s the string to encode
	/// @return the US-ASCII bytes of {@code s}
	/// @throws IllegalArgumentException if {@code s} contains any character outside the US-ASCII range
	public static byte[] strictBytes(String s) {
		var encoder = StandardCharsets.US_ASCII.newEncoder()
				.onMalformedInput(CodingErrorAction.REPORT)
				.onUnmappableCharacter(CodingErrorAction.REPORT);
		try {
			var encoded = encoder.encode(CharBuffer.wrap(s));
			var bytes = new byte[encoded.remaining()];
			encoded.get(bytes);
			return bytes;
		} catch (CharacterCodingException e) {
			throw new IllegalArgumentException("Expected US-ASCII, but string contains non-ASCII characters", e);
		}
	}

}
