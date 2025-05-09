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

}
