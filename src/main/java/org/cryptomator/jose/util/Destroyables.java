package org.cryptomator.jose.util;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

public class Destroyables {

	private Destroyables() {
		// Utility class
	}

	public static void destroyQuietly(Destroyable destroyable) {
		if (destroyable != null) {
			try {
				destroyable.destroy();
			} catch (DestroyFailedException e) {
				// Ignore
			}
		}
	}
}
