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

}
