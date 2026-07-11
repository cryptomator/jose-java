package org.cryptomator.jose.hpke;

import org.cryptomator.jose.util.Curve;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class HPKEContextTest {

	private HPKE.Context senderContext() {
		var keyPair = Curve.P256.generateKeyPair(); // hpke0 = DHKEM(P-256)
		return HPKE.hpke0().setupBaseS(keyPair.getPublic(), new byte[0]).context();
	}

	@Test
	@DisplayName("seal still succeeds at the last sequence number with a distinct nonce")
	void testLastValidSequence() {
		try (var ctx = senderContext()) {
			ctx.sequence = (1L << 32) - 1; // low 4 bytes = 0xFFFFFFFF, still distinct from every earlier nonce
			Assertions.assertDoesNotThrow(() -> ctx.seal(new byte[0], new byte[0]));
		}
	}

	@Test
	@DisplayName("seal refuses once the sequence number would wrap and reuse a nonce")
	void testMessageLimitSeal() {
		try (var ctx = senderContext()) {
			ctx.sequence = 1L << 32; // the low 4 bytes would wrap back to 0x00000000, reusing sequence 0's nonce
			Assertions.assertThrows(IllegalStateException.class, () -> ctx.seal(new byte[0], new byte[0]));
		}
	}

	@Test
	@DisplayName("open refuses once the sequence number would wrap and reuse a nonce")
	void testMessageLimitOpen() {
		try (var ctx = senderContext()) {
			ctx.sequence = 1L << 32;
			Assertions.assertThrows(IllegalStateException.class, () -> ctx.open(new byte[0], new byte[0]));
		}
	}
}
