package org.cryptomator.jose.util;

import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import org.cryptomator.jose.JoseParseException;

import java.io.IOException;
import java.io.StringReader;

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

	/// Parses a JSON text that must be exactly one JSON object, in strict mode ([RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)): no comments, unquoted names, single quotes or trailing content,
	/// all of which Gson's default lenient parsing would accept although conforming JOSE implementations reject them.
	///
	/// @param json The JSON text
	/// @return The parsed object
	/// @throws JoseParseException if the text is not valid strict JSON or not an object
	public static JsonObject parseObject(String json) throws JoseParseException {
		try {
			var reader = new JsonReader(new StringReader(json));
			reader.setStrictness(Strictness.STRICT);
			var element = JsonParser.parseReader(reader);
			if (reader.peek() != JsonToken.END_DOCUMENT) {
				throw new JoseParseException("Unexpected content after JSON object");
			}
			if (!element.isJsonObject()) {
				throw new JoseParseException("JSON must be an object");
			}
			return element.getAsJsonObject();
		} catch (JsonParseException | IOException e) { // JsonParser wraps MalformedJsonException; peek() declares IOException
			throw new JoseParseException("Invalid JSON", e);
		}
	}

	/// Returns the value of the given member, requiring it to be present and a JSON string (Gson's `getAsString()` would throw unchecked exceptions for objects, arrays and null).
	///
	/// @param json The object to read from
	/// @param key The member name
	/// @return The member's string value
	/// @throws JoseParseException if the member is missing or not a JSON string
	public static String requireString(JsonObject json, String key) throws JoseParseException {
		var element = json.get(key);
		if (element == null || !element.isJsonPrimitive() || !element.getAsJsonPrimitive().isString()) {
			throw new JoseParseException("JSON must contain a string '" + key + "' member");
		}
		return element.getAsString();
	}

}
