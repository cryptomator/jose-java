package org.cryptomator.jose;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Objects;

/// A pre-shared key for HPKE `mode_psk` ([draft-ietf-hpke-hpke, Section 5.1.2](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.1.2)),
/// which authenticates the sender towards the recipient as a holder of the key. Attach it to an HPKE algorithm with its `withPsk` method; the identifier then
/// travels as the `psk_id` header parameter ([draft-ietf-jose-hpke-encrypt, Section 11.2.2](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/#section-11.2.2)),
/// and the recipient must hold a PSK with the same identifier.
///
/// The PSK MUST have at least 32 bytes of entropy and SHOULD be at least `Nh` bytes long, i.e. 32 bytes for `HPKE-0`, 48 for `HPKE-1` and 64 for `HPKE-2` and `HPKE-9`
/// ([draft-ietf-hpke-hpke, Section 9.5](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-9.5)). HPKE's PSK mode is not suitable for
/// low-entropy secrets such as passwords; derive a key from those first. Neither requirement is enforced here, only non-empty inputs are.
///
/// @param key The pre-shared key, which remains owned (and eventually destroyed) by the caller; must be extractable
/// @param id The PSK identifier (`psk_id`), copied on construction
public record Psk(SecretKey key, byte[] id) {

	/// @throws IllegalArgumentException if the key is not extractable or empty, or the identifier is empty
	public Psk {
		Objects.requireNonNull(key, "key");
		Objects.requireNonNull(id, "id");
		if (id.length == 0) {
			throw new IllegalArgumentException("psk_id must not be empty"); // VerifyPSKInputs: a PSK without identifier is inconsistent
		}
		var encoded = key.getEncoded();
		if (encoded == null) {
			throw new IllegalArgumentException("PSK must be extractable");
		}
		try {
			if (encoded.length == 0) {
				throw new IllegalArgumentException("PSK must not be empty");
			}
		} finally {
			Arrays.fill(encoded, (byte) 0x00);
		}
		id = id.clone();
	}

	@Override
	public byte[] id() {
		return id.clone();
	}

	@Override
	public boolean equals(Object obj) {
		return obj instanceof Psk(SecretKey otherKey, byte[] otherId) && key.equals(otherKey) && Arrays.equals(id, otherId);
	}

	@Override
	public int hashCode() {
		return 31 * key.hashCode() + Arrays.hashCode(id);
	}

	@Override
	public String toString() {
		return "Psk[key=<redacted>, id=" + id.length + " bytes]";
	}

}
