package org.cryptomator.jose.hpke;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/// Initializes an X-Wing [java.security.KeyPairGenerator] with a fixed 32-byte seed instead of fresh randomness, so that the generated key pair is the one
/// deterministically expanded from that seed ([draft-connolly-cfrg-xwing-kem, Section 5.2](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-07#section-5.2)).
/// Used to recover the public key that belongs to a serialized private key (which is just the seed), e.g. to verify an AKP JWK's `pub` against its `priv`.
public final class XwingSeedParameterSpec implements AlgorithmParameterSpec {

	private final byte[] seed;

	/// @param seed The 32-byte X-Wing seed `sk`; the spec keeps its own copy
	/// @throws IllegalArgumentException if the seed is not 32 bytes long
	public XwingSeedParameterSpec(byte[] seed) {
		if (seed == null || seed.length != 32) {
			throw new IllegalArgumentException("X-Wing seed must be 32 bytes long");
		}
		this.seed = seed.clone();
	}

	byte[] seed() {
		return seed.clone();
	}

	/// Wipes the copied seed.
	public void destroy() {
		Arrays.fill(seed, (byte) 0);
	}

}
