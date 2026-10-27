package org.cryptomator.jose.alg;

import com.google.gson.JsonObject;
import org.cryptomator.jose.Psk;
import org.cryptomator.jose.util.Base64Url;

import java.security.MessageDigest;
import java.util.Arrays;

/// The HPKE mode of a JWE recipient is signalled by the `psk_id` header parameter ([draft-ietf-jose-hpke-encrypt, Section 3](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-3)):
/// present means `mode_psk`, absent means `mode_base`. Mirrors HPKE's `VerifyPSKInputs` on the JOSE level, where the configured [Psk] takes the role of the PSK input.
final class PskMode {

	static final String PSK_ID = "psk_id";

	private PskMode() {
	}

	/// Checks that the token's mode matches the configured PSK (if any) and, in `mode_psk`, that `psk_id` names that PSK.
	///
	/// @param combinedHeader The recipient's combined JOSE Header
	/// @param psk The configured PSK, or `null` for `mode_base`
	/// @throws DecryptKeyException on a mode mismatch, a malformed `psk_id`, or a `psk_id` naming another PSK
	static void verify(JsonObject combinedHeader, Psk psk) throws DecryptKeyException {
		var pskIdHeader = combinedHeader.get(PSK_ID);
		if (pskIdHeader == null) {
			if (psk != null) {
				throw new DecryptKeyException("A PSK is configured, but the recipient uses HPKE mode_base (no psk_id header)");
			}
			return;
		}
		if (psk == null) {
			throw new DecryptKeyException("The recipient uses HPKE mode_psk (psk_id header present), but no PSK is configured");
		}
		if (!pskIdHeader.isJsonPrimitive() || !pskIdHeader.getAsJsonPrimitive().isString()) {
			throw new DecryptKeyException("Non-string psk_id header");
		}
		final byte[] pskId;
		try {
			pskId = Base64Url.decode(pskIdHeader.getAsString());
		} catch (IllegalArgumentException e) {
			throw new DecryptKeyException("psk_id header is not base64url", e);
		}
		var configuredId = psk.id();
		try {
			if (!MessageDigest.isEqual(pskId, configuredId)) {
				throw new DecryptKeyException("psk_id does not name the configured PSK");
			}
		} finally {
			Arrays.fill(configuredId, (byte) 0x00);
		}
	}

	/// @return The `psk_id` header value for the PSK
	static String headerValue(Psk psk) {
		return Base64Url.encode(psk.id());
	}

}
