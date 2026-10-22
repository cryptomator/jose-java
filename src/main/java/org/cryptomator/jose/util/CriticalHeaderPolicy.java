package org.cryptomator.jose.util;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.LinkedHashSet;
import java.util.Set;

/// Validation of the `crit` (Critical) header parameter as specified in [RFC 7515, Section 4.1.11](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11)
/// and [RFC 7516, Section 4.1.13](https://www.rfc-editor.org/rfc/rfc7516#section-4.1.13): a consumer must reject a JWE/JWS that lists an extension
/// it does not understand, and `crit` itself must be integrity protected.
public final class CriticalHeaderPolicy {

	/// Header parameter names defined by RFC 7515, RFC 7516 and RFC 7518, which must not be listed in `crit`. Parameters registered by other
	/// specifications (e.g. `ek` from the JOSE HPKE draft) are legitimate `crit` entries.
	public static final Set<String> REGISTERED = Set.of(
			"alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit", // RFC 7515 §4.1
			"enc", "zip", // RFC 7516 §4.1
			"epk", "apu", "apv", "iv", "tag", "p2s", "p2c" // RFC 7518 §4.6.1, §4.7.1, §4.8.1
	);

	/// Extension header parameters this library implements and therefore always understands: `ek` from
	/// [draft-ietf-jose-hpke-encrypt, Section 11.2](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-11.2).
	/// `psk_id` from the same registry is deliberately absent, as the HPKE PSK modes are not implemented.
	public static final Set<String> IMPLEMENTED_EXTENSIONS = Set.of("ek");

	private CriticalHeaderPolicy() {
	}

	/// Validates the `crit` parameter of an integrity-protected header, if present.
	///
	/// @param protectedHeader The decoded protected header
	/// @param understood The extension header parameter names the consumer (including its algorithms) understands
	/// @return The critical header parameter names, empty if `crit` is absent
	/// @throws IllegalArgumentException if `crit` is not a non-empty array of unique strings, lists a registered name, or lists a name the consumer does not understand
	public static Set<String> validate(JsonObject protectedHeader, Set<String> understood) throws IllegalArgumentException {
		var crit = protectedHeader.get("crit");
		if (crit == null) {
			return Set.of();
		}
		if (!crit.isJsonArray() || crit.getAsJsonArray().isEmpty()) {
			throw new IllegalArgumentException("crit must be a non-empty array");
		}
		var names = new LinkedHashSet<String>();
		for (JsonElement element : crit.getAsJsonArray()) {
			if (!element.isJsonPrimitive() || !element.getAsJsonPrimitive().isString()) {
				throw new IllegalArgumentException("crit must only contain strings");
			}
			var name = element.getAsString();
			if (REGISTERED.contains(name)) {
				throw new IllegalArgumentException("crit must not list the registered header parameter '" + name + "'");
			}
			if (!names.add(name)) {
				throw new IllegalArgumentException("crit must not list '" + name + "' twice");
			}
			if (!understood.contains(name)) {
				throw new IllegalArgumentException("Critical header parameter '" + name + "' is not understood");
			}
		}
		return Set.copyOf(names);
	}

	/// Ensures every critical header parameter actually occurs in the JOSE Header, as RFC 7515 Section 4.1.11 requires of producers.
	///
	/// @param crit The critical header parameter names returned by [#validate]
	/// @param joseHeader The complete JOSE Header (for JWE: protected, shared unprotected and per-recipient header combined)
	/// @throws IllegalArgumentException if a critical parameter is missing from the header
	public static void ensurePresent(Set<String> crit, JsonObject joseHeader) throws IllegalArgumentException {
		for (var name : crit) {
			if (!joseHeader.has(name)) {
				throw new IllegalArgumentException("Critical header parameter '" + name + "' is listed in crit but absent from the header");
			}
		}
	}

}
