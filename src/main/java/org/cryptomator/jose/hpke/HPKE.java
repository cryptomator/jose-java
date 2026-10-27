package org.cryptomator.jose.hpke;

import org.cryptomator.jose.Psk;
import org.cryptomator.jose.util.ArrayUtil;
import org.cryptomator.jose.util.Destroyables;

import javax.crypto.AEADBadTagException;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

/// An HPKE ciphersuite (KEM, KDF, AEAD) as defined in [draft-ietf-hpke-hpke](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03), offering the
/// `mode_base` and `mode_psk` sender and recipient setups (`mode_auth` and `mode_auth_psk` are not supported). The static factory methods provide the suites registered for JOSE in
/// [draft-ietf-jose-hpke-encrypt](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/) and
/// [draft-ietf-jose-hpke-pq-pqt](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-pq-pqt/); `baseName` is the JOSE `alg` name of the suite's
/// Integrated Encryption variant (the Key Encryption variant appends `-KE`).
public final class HPKE {

	/// HPKE modes as defined in [draft-ietf-hpke-hpke, Table 1](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5)
	public static final byte MODE_BASE = 0x00;
	public static final byte MODE_PSK = 0x01;

	private static final byte[] EMPTY = new byte[0];

	private final String baseName;
	private final KEM kem;
	private final Kdf kdf;
	private final AEAD aead;
	private final byte[] suiteId;

	private HPKE(String baseName, KEM kem, Kdf kdf, AEAD aead, byte[] suiteId) {
		this.baseName = baseName;
		this.kem = kem;
		this.kdf = kdf;
		this.aead = aead;
		this.suiteId = suiteId;
	}

	/// DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
	public static HPKE hpke0() {
		return new HPKE("HPKE-0", dhkem(), HKDF.sha256(), AEAD.AES128GCM, suiteId(0x0010, 0x0001, 0x0001));
	}

	/// DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, AES-256-GCM
	public static HPKE hpke1() {
		return new HPKE("HPKE-1", dhkem(), HKDF.sha384(), AEAD.AES256GCM, suiteId(0x0011, 0x0002, 0x0002));
	}

	/// DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM
	public static HPKE hpke2() {
		return new HPKE("HPKE-2", dhkem(), HKDF.sha512(), AEAD.AES256GCM, suiteId(0x0012, 0x0003, 0x0002));
	}

	/// MLKEM768-X25519 (a.k.a. X-Wing), SHAKE256, AES-256-GCM
	public static HPKE hpke9() {
		return new HPKE("HPKE-9", xwing(), Shake.SHAKE256, AEAD.AES256GCM, suiteId(0x647a, 0x0011, 0x0002));
	}

	/// The `suite_id` used within the labeled derivation functions, as defined in [draft-ietf-hpke-hpke, Section 5.1](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.1);
	/// KEM/KDF/AEAD IDs per the [IANA HPKE registry](https://www.iana.org/assignments/hpke/hpke.xhtml) and [draft-ietf-hpke-pq](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05)
	private static byte[] suiteId(int kemId, int kdfId, int aeadId) {
		return new byte[]{
				'H', 'P', 'K', 'E', //
				(byte) (kemId >>> 8), (byte) kemId, //
				(byte) (kdfId >>> 8), (byte) kdfId, //
				(byte) (aeadId >>> 8), (byte) aeadId //
		};
	}

	private static KEM dhkem() {
		try {
			return KEM.getInstance("DHKEM");
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("JVM does not support DHKEM", e);
		}
	}

	private static KEM xwing() {
		try {
			return KEM.getInstance("X-Wing", XwingProvider.INSTANCE);
		} catch (NoSuchAlgorithmException e) {
			throw new AssertionError("Custom X-Wing provider must support X-Wing KEM", e);
		}
	}

	public String baseName() {
		return baseName;
	}

	/// `SetupBaseS` or, with a PSK, `SetupPSKS` as defined in [draft-ietf-hpke-hpke, Section 5.1.1](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.1.1)
	/// and [Section 5.1.2](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.1.2): encapsulates a shared secret for `pkR` and derives the
	/// sender's encryption context; in `mode_psk` the pre-shared key is mixed into the key schedule, which authenticates the sender as a holder of that key.
	///
	/// @param pkR The recipient's public key
	/// @param info Application-supplied information
	/// @param psk The pre-shared key for `mode_psk`, or `null` for `mode_base`
	/// @return The encapsulated secret and the sender's context
	public Sender setupS(PublicKey pkR, byte[] info, Psk psk) { // TODO: mark psk as nullable
		return setupS(pkR, info, psk, null);
	}

	// visible for testing: a fixed SecureRandom makes the KEM encapsulation reproducible against test vectors
	Sender setupS(PublicKey pkR, byte[] info, Psk psk, SecureRandom random) {
		KEM.Encapsulated encapsulated;
		try {
			encapsulated = kem.newEncapsulator(pkR, random).encapsulate(); // null random: the provider's default
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Invalid receiver public key for " + kem.getAlgorithm(), e);
		}
		var sharedSecret = DestroyableSecretKey.copyOf(encapsulated.key()); // the JDK's DHKEM returns a SecretKeySpec, which cannot be wiped; our copy can
		try {
			return new Sender(encapsulated.encapsulation(), keySchedule(sharedSecret, info, psk));
		} finally {
			sharedSecret.destroy();
			Destroyables.destroyQuietly(encapsulated.key()); // a no-op for SecretKeySpec, but harmless
		}
	}

	/// `SetupBaseR` or, with a PSK, `SetupPSKR` as defined in [draft-ietf-hpke-hpke, Section 5.1.1](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.1.1)
	/// and [Section 5.1.2](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.1.2): decapsulates `enc` with `skR` and derives the recipient's
	/// encryption context; in `mode_psk` opening only succeeds if the sender used the same pre-shared key.
	///
	/// @param enc The encapsulated secret
	/// @param skR The recipient's private key
	/// @param info Application-supplied information
	/// @param psk The pre-shared key for `mode_psk`, or `null` for `mode_base`
	/// @return The recipient's context
	/// @throws DecapsulateException if `enc` cannot be decapsulated
	public Context setupR(byte[] enc, PrivateKey skR, byte[] info, Psk psk) throws DecapsulateException { // TODO: mark psk as nullable
		SecretKey decapsulated;
		try {
			decapsulated = kem.newDecapsulator(skR).decapsulate(enc);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Invalid receiver private key for " + kem.getAlgorithm(), e);
		}
		var sharedSecret = DestroyableSecretKey.copyOf(decapsulated); // the JDK's DHKEM returns a SecretKeySpec, which cannot be wiped; our copy can
		try {
			return keySchedule(sharedSecret, info, psk);
		} finally {
			sharedSecret.destroy();
			Destroyables.destroyQuietly(decapsulated); // a no-op for SecretKeySpec, but harmless
		}
	}

	/// @param enc the encapsulated secret to be transmitted to the recipient
	/// @param context the sender's encryption context
	public record Sender(byte[] enc, Context context) {
	}

	// the mode follows from the presence of a PSK; its bytes only live for the duration of the key schedule
	private Context keySchedule(SecretKey sharedSecret, byte[] info, Psk psk) { // TODO: mark psk as nullable
		if (psk == null) {
			return keySchedule(MODE_BASE, sharedSecret, info, EMPTY, EMPTY);
		}
		var pskBytes = psk.key().getEncoded();
		try {
			return keySchedule(MODE_PSK, sharedSecret, info, pskBytes, psk.id());
		} finally {
			Arrays.fill(pskBytes, (byte) 0x00);
		}
	}

	/// creates an encryption context as defined in [draft-ietf-hpke-hpke, Section 5.1](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.1)
	///
	/// @param mode A one-byte value indicating the HPKE mode, defined in Table 1.
	/// @param sharedSecret A KEM shared secret generated for this transaction.
	/// @param info Application-supplied information (optional).
	/// @param psk A pre-shared key (PSK) held by both the sender and the recipient; empty in `mode_base`, non-empty in `mode_psk`
	/// @param pskId An identifier for the PSK; empty in `mode_base`, non-empty in `mode_psk`
	/// @throws IllegalArgumentException if the PSK inputs do not match the mode (`VerifyPSKInputs`)
	/// @throws UnsupportedOperationException for `mode_auth` and `mode_auth_psk`
	// visible for testing
	Context keySchedule(byte mode, SecretKey sharedSecret, byte[] info, byte[] psk, byte[] pskId) {
		if (mode != MODE_BASE && mode != MODE_PSK) {
			throw new UnsupportedOperationException("Only mode_base and mode_psk are supported (no mode_auth or mode_auth_psk)");
		}
		// VerifyPSKInputs, draft-ietf-hpke-hpke Section 5.1:
		var gotPsk = psk.length > 0;
		var gotPskId = pskId.length > 0;
		if (gotPsk != gotPskId) {
			throw new IllegalArgumentException("Inconsistent PSK inputs");
		}
		if (gotPsk && mode == MODE_BASE) {
			throw new IllegalArgumentException("PSK input provided when not needed");
		}
		if (!gotPsk && mode == MODE_PSK) {
			throw new IllegalArgumentException("Missing required PSK input");
		}

		var derived = kdf.combineSecrets(mode, sharedSecret, info, psk, pskId, suiteId, "AES", aead.nk, aead.nn);
		return new Context(derived.key(), derived.baseNonce());
	}

	/// An HPKE encryption context as defined in [draft-ietf-hpke-hpke, Section 5.2](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.2).
	/// [#close()] wipes the AEAD key this context holds (best effort: copies inside the JDK cipher are outside its control); afterwards [#seal]/[#open] fail.
	public final class Context implements AutoCloseable, Destroyable {
		private static final long MESSAGE_LIMIT = (1L << 32) - 1; // this implementation encodes the sequence number in the low 4 bytes of the nonce; refuse further messages before it would wrap and reuse a nonce (draft-ietf-hpke-hpke Section 5.2)

		private final SecretKey key;
		private final byte[] baseNonce;
		long sequence = 0; // visible for testing

		private Context(SecretKey key, byte[] baseNonce) {
			this.key = key;
			this.baseNonce = baseNonce;
		}

		public byte[] seal(byte[] aad, byte[] pt) {
			// https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.2
			if (sequence > MESSAGE_LIMIT) {
				throw new IllegalStateException("HPKE message limit reached");
			}
			try {
				return aead.seal(this.key, this.computeNonce(), aad, pt);
			} finally {
				sequence++;
			}
		}

		public byte[] open(byte[] aad, byte[] ct) throws AEADBadTagException {
			// https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.2
			if (sequence > MESSAGE_LIMIT) {
				throw new IllegalStateException("HPKE message limit reached");
			}
			try {
				return aead.open(this.key, this.computeNonce(), aad, ct);
			} finally {
				sequence++;
			}
		}

		private byte[] computeNonce() {
			var seqBytes = new byte[aead.nn];
			var seqBuf = ByteBuffer.wrap(seqBytes);
			seqBuf.putInt(seqBytes.length - Integer.BYTES, (int) sequence);
			return ArrayUtil.xor(baseNonce, seqBytes);
		}

		@Override
		public void destroy() {
			Destroyables.destroyQuietly(key);
		}

		@Override
		public boolean isDestroyed() {
			return key.isDestroyed();
		}

		@Override
		public void close() {
			destroy();
		}
	}

}
