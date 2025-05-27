package org.cryptomator.jose.util;

import java.util.Arrays;

public class ArrayUtil {

	private ArrayUtil() {
		// prevent instantiation
	}

	public static byte[] concat(byte[] a, byte[] b) {
		byte[] result = new byte[a.length + b.length];
		System.arraycopy(a, 0, result, 0, a.length);
		System.arraycopy(b, 0, result, a.length, b.length);
		return result;
	}

	public static byte[] concat(byte[] ... bytes) {
		if (bytes.length == 0) {
			return new byte[0];
		} else if (bytes.length == 1) {
			return bytes[0];
		} else {
			byte[] result = new byte[0];
			for (byte[] b : bytes) {
				result = concat(result, b);
			}
			return result;
		}
	}

	public static byte[] xor(byte[] a, byte[] b) {
		if (a.length != b.length) {
			throw new IllegalArgumentException("Arrays must be of the same length");
		}
		byte[] result = new byte[a.length];
		for (int i = 0; i < a.length; i++) {
			result[i] = (byte) (a[i] ^ b[i]);
		}
		return result;
	}

	public static byte[] reverse(byte[] input) {
		byte[] reversed = new byte[input.length];
		for (int i = 0; i < input.length; i++) {
			reversed[i] = input[input.length - 1 - i];
		}
		return reversed;
	}

	/// Find position of needle in haystack
	/// @param haystack the array to search in
	/// @param needle the array to search for
	/// @return the start of the first occurrence of needle in haystack, or -1 if not found
	public static int indexOf(byte[] haystack, byte[] needle) {
		for (int i = 0; i <= haystack.length - needle.length; i++) {
			if (Arrays.equals(haystack, i, i + needle.length, needle, 0, needle.length)) {
				return i;
			}
		}
		return -1; // not found
	}
}
