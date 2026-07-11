package org.cryptomator.jose.util;

import com.google.gson.JsonObject;

public class JsonHelper {

	private JsonHelper(){}

	/**
	 * Merges two JSON objects into a new one.
	 *
	 * @param left  One JSON object.
	 * @param right Another JSON object.
	 * @return A new JSON object containing all entries from both input objects.
	 * @implNote When a key is present in both input objects, the {@code left} object's value is used.
	 */
	public static JsonObject union(JsonObject left, JsonObject right) {
		var union = new JsonObject();
		right.entrySet().forEach(e -> union.add(e.getKey(), e.getValue()));
		left.entrySet().forEach(e -> union.add(e.getKey(), e.getValue()));
		return union;
	}

	/// Merges two JSON objects into a new one, requiring their key sets to be disjoint. Used to assemble a JWE JOSE Header from the protected,
	/// shared unprotected, and per-recipient unprotected headers, which [RFC 7516 Section 4](https://www.rfc-editor.org/rfc/rfc7516#section-4)
	/// requires to be free of duplicate Header Parameter names.
	///
	/// @throws IllegalArgumentException if a key is present in both objects (a precondition violation; callers handling untrusted input should convert this to a checked exception)
	public static JsonObject disjointUnion(JsonObject a, JsonObject b) throws IllegalArgumentException {
		var duplicateKey = a.keySet().stream().filter(b::has).findAny();
		if (duplicateKey.isPresent()) {
			throw new IllegalArgumentException("Duplicate header parameter: " + duplicateKey.get());
		}
		return union(a, b);
	}

}
