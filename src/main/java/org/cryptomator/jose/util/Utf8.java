package org.cryptomator.jose.util;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/// Strict UTF-8 decoding. Unlike `new String(bytes, UTF_8)`, this rejects malformed input instead of silently substituting U+FFFD,
/// as required for JOSE Headers by [RFC 7515, Section 5.2](https://www.rfc-editor.org/rfc/rfc7515#section-5.2) and [RFC 7516, Section 5.2](https://www.rfc-editor.org/rfc/rfc7516#section-5.2).
public final class Utf8 {

	private Utf8() {
	}

	/// Decodes the given bytes as UTF-8.
	///
	/// @param bytes The UTF-8 encoded bytes
	/// @return The decoded string
	/// @throws IllegalArgumentException if the bytes are not well-formed UTF-8
	public static String strictString(byte[] bytes) {
		var decoder = StandardCharsets.UTF_8.newDecoder()
				.onMalformedInput(CodingErrorAction.REPORT)
				.onUnmappableCharacter(CodingErrorAction.REPORT);
		try {
			return decoder.decode(ByteBuffer.wrap(bytes)).toString();
		} catch (CharacterCodingException e) {
			throw new IllegalArgumentException("Expected UTF-8, but input is malformed", e);
		}
	}

}
