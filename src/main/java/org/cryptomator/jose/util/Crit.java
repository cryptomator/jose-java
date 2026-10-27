package org.cryptomator.jose.util;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.LinkedHashSet;
import java.util.Set;

/// The `crit` (Critical) header parameter as specified in [RFC 7515, Section 4.1.11](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11)
/// and [RFC 7516, Section 4.1.13](https://www.rfc-editor.org/rfc/rfc7516#section-4.1.13). The two sides have different obligations, hence [Builder] for
/// producers and [Parser] for consumers; both rely on the same structural checks.
public final class Crit {

	/// Header parameter names defined by RFC 7515, RFC 7516 and RFC 7518, which must not be listed in `crit`. Parameters registered by other
	/// specifications (e.g. `ek` from the JOSE HPKE draft) are legitimate `crit` entries.
	public static final Set<String> REGISTERED = Set.of(
			"alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit", // RFC 7515 §4.1
			"enc", "zip", // RFC 7516 §4.1
			"epk", "apu", "apv", "iv", "tag", "p2s", "p2c" // RFC 7518 §4.6.1, §4.7.1, §4.8.1
	);

	/// Extension header parameters this library implements and therefore always understands: `ek` and `psk_id` from
	/// [draft-ietf-jose-hpke-encrypt, Section 11.2](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-11.2).
	public static final Set<String> IMPLEMENTED_EXTENSIONS = Set.of("ek", "psk_id");

	private Crit() {
	}

	/// Obligations of a producer ([RFC 7515, Section 4.1.11](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11)): `crit` must be well-formed, must not
	/// list registered names, must name only parameters that are present, and must itself be integrity protected. Any extension name is acceptable, since the
	/// producer decides which extensions it uses.
	public static final class Builder {

		private Builder() {
		}

		/// Validates the structure of the `crit` parameter of the protected header, if present.
		///
		/// @param protectedHeader The protected header
		/// @return The critical header parameter names, empty if `crit` is absent
		/// @throws IllegalArgumentException if `crit` is not a non-empty array of unique strings, or lists a registered name
		public static Set<String> validate(JsonObject protectedHeader) throws IllegalArgumentException {
			return parseCrit(protectedHeader);
		}

		/// Ensures every critical header parameter actually occurs in the JOSE Header; for a multi-recipient JWE, call once per recipient.
		///
		/// @param crit The critical header parameter names returned by [#validate]
		/// @param joseHeader The complete JOSE Header (for JWE: protected, shared unprotected and per-recipient header combined)
		/// @throws IllegalArgumentException if a critical parameter is missing from the header
		public static void ensurePresent(Set<String> crit, JsonObject joseHeader) throws IllegalArgumentException {
			Crit.ensurePresent(crit, joseHeader);
		}

		/// Rejects `crit` outside the protected header, where it would not be integrity protected ([RFC 7516, Section 4.1.13](https://www.rfc-editor.org/rfc/rfc7516#section-4.1.13)).
		///
		/// @param unprotectedHeader A shared unprotected or per-recipient header supplied by the producer
		/// @param location Name of the header for the error message
		/// @throws IllegalArgumentException if the header contains `crit`
		public static void rejectUnprotected(JsonObject unprotectedHeader, String location) throws IllegalArgumentException {
			if (unprotectedHeader.has("crit")) {
				throw new IllegalArgumentException("crit must be in the protected header, not in the " + location);
			}
		}

	}

	/// Obligations of a consumer ([RFC 7515, Section 4.1.11](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11)): everything a producer must guarantee,
	/// plus rejecting any critical extension the consumer (including its algorithms) does not understand.
	public static final class Parser {

		private Parser() {
		}

		/// Validates the `crit` parameter of the protected header, if present.
		///
		/// @param protectedHeader The decoded protected header
		/// @param understood The extension header parameter names the consumer understands
		/// @return The critical header parameter names, empty if `crit` is absent
		/// @throws IllegalArgumentException if `crit` is not a non-empty array of unique strings, lists a registered name, or lists a name the consumer does not understand
		public static Set<String> validate(JsonObject protectedHeader, Set<String> understood) throws IllegalArgumentException {
			var names = parseCrit(protectedHeader);
			for (var name : names) {
				if (!understood.contains(name)) {
					throw new IllegalArgumentException("Critical header parameter '" + name + "' is not understood");
				}
			}
			return names;
		}

		/// Ensures every critical header parameter actually occurs in the JOSE Header; for a multi-recipient JWE, call once per recipient.
		///
		/// @param crit The critical header parameter names returned by [#validate]
		/// @param joseHeader The complete JOSE Header (for JWE: protected, shared unprotected and per-recipient header combined)
		/// @throws IllegalArgumentException if a critical parameter is missing from the header
		public static void ensurePresent(Set<String> crit, JsonObject joseHeader) throws IllegalArgumentException {
			Crit.ensurePresent(crit, joseHeader);
		}

	}

	// the structural rules shared by both sides: a non-empty array of unique strings naming no registered header parameter
	private static Set<String> parseCrit(JsonObject protectedHeader) throws IllegalArgumentException {
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
		}
		return Set.copyOf(names);
	}

	private static void ensurePresent(Set<String> crit, JsonObject joseHeader) throws IllegalArgumentException {
		for (var name : crit) {
			if (!joseHeader.has(name)) {
				throw new IllegalArgumentException("Critical header parameter '" + name + "' is listed in crit but absent from the header");
			}
		}
	}

}
