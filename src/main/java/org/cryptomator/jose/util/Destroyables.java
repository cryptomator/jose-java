package org.cryptomator.jose.util;

import org.jspecify.annotations.Nullable;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

/// Best-effort wiping of key material: `destroy()` only has an effect on implementations that support it (this library's [org.cryptomator.jose.hpke.DestroyableSecretKey]
/// and the JDK's PBKDF2 keys do; `SecretKeySpec` does not, its `destroy()` merely throws), so callers that hold raw `byte[]` should zero those themselves.
public class Destroyables {

	private Destroyables() {
		// Utility class
	}

	public static void destroyQuietly(@Nullable Destroyable destroyable) {
		if (destroyable != null) {
			try {
				destroyable.destroy();
			} catch (DestroyFailedException _) {
				// Ignore
			}
		}
	}
}
