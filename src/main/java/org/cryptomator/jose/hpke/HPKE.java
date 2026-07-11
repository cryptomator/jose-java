package org.cryptomator.jose.hpke;

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

/// An HPKE ciphersuite (KEM, KDF, AEAD) as defined in [draft-ietf-hpke-hpke](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03), offering the base mode
/// sender and recipient setup. The static factory methods provide the suites registered for JOSE in
/// [draft-ietf-jose-hpke-encrypt](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/) and
/// [draft-ietf-jose-hpke-pq-pqt](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-pq-pqt/); `baseName` is the JOSE `alg` name of the suite's
/// Integrated Encryption variant (the Key Encryption variant appends `-KE`).
public final class HPKE {

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

	/// `SetupBaseS` as defined in [draft-ietf-hpke-hpke, Section 5.1.1](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.1.1):
	/// encapsulates a shared secret for `pkR` and derives the sender's encryption context.
	public Sender setupBaseS(PublicKey pkR, byte[] info) {
		KEM.Encapsulated encapsulated;
		try {
			encapsulated = kem.newEncapsulator(pkR).encapsulate();
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Invalid receiver public key for " + kem.getAlgorithm(), e);
		}
		var sharedSecret = encapsulated.key();
		try {
			return new Sender(encapsulated.encapsulation(), keySchedule((byte) 0x00, sharedSecret, info, new byte[0], new byte[0]));
		} finally {
			Destroyables.destroyQuietly(sharedSecret);
		}
	}

	/// `SetupBaseR` as defined in [draft-ietf-hpke-hpke, Section 5.1.1](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.1.1):
	/// decapsulates `enc` with `skR` and derives the recipient's encryption context.
	public Context setupBaseR(byte[] enc, PrivateKey skR, byte[] info) throws DecapsulateException {
		SecretKey sharedSecret;
		try {
			sharedSecret = kem.newDecapsulator(skR).decapsulate(enc);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Invalid receiver private key for " + kem.getAlgorithm(), e);
		}
		try {
			return keySchedule((byte) 0x00, sharedSecret, info, new byte[0], new byte[0]);
		} finally {
			Destroyables.destroyQuietly(sharedSecret);
		}
	}

	/// @param enc the encapsulated secret to be transmitted to the recipient
	/// @param context the sender's encryption context
	public record Sender(byte[] enc, Context context) {
	}

	/// creates an encryption context as defined in [draft-ietf-hpke-hpke, Section 5.1](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.1)
	///
	/// @param mode A one-byte value indicating the HPKE mode, defined in Table 1.
	/// @param sharedSecret A KEM shared secret generated for this transaction.
	/// @param info Application-supplied information (optional).
	/// @param psk A pre-shared key (PSK) held by both the sender and the recipient (optional).
	/// @param pskId An identifier for the PSK (optional).
	// visible for testing
	Context keySchedule(byte mode, SecretKey sharedSecret, byte[] info, byte[] psk, byte[] pskId) {
		if ((psk.length == 0) != (pskId.length == 0)) {
			throw new IllegalArgumentException("Inconsistent PSK inputs");
		}
		if (mode == 0x00 && psk.length > 0) { // mode_base
			throw new IllegalArgumentException("PSK input provided when not needed");
		}
		if (mode != 0x00) {
			throw new UnsupportedOperationException("Only mode_base is currently supported");
		}

		var derived = kdf.combineSecrets(mode, sharedSecret, info, psk, pskId, suiteId, "AES", aead.nk, aead.nn);
		return new Context(derived.key(), derived.baseNonce());
	}

	/// An HPKE encryption context as defined in [draft-ietf-hpke-hpke, Section 5.2](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.2),
	/// holding key material that is destroyed on [#close()].
	public final class Context implements AutoCloseable, Destroyable {
		private final SecretKey key;
		private final byte[] baseNonce;
		private int sequence = 0;

		private Context(SecretKey key, byte[] baseNonce) {
			this.key = key;
			this.baseNonce = baseNonce;
		}

		public byte[] seal(byte[] aad, byte[] pt) {
			// https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.2
			try {
				return aead.seal(this.key, this.computeNonce(), aad, pt);
			} finally {
				sequence++;
			}
		}

		public byte[] open(byte[] aad, byte[] ct) throws AEADBadTagException {
			// https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.2
			try {
				return aead.open(this.key, this.computeNonce(), aad, ct);
			} finally {
				sequence++;
			}
		}

		private byte[] computeNonce() {
			var seqBytes = new byte[aead.nn];
			var seqBuf = ByteBuffer.wrap(seqBytes);
			seqBuf.putInt(seqBytes.length - Integer.BYTES, sequence);
			return ArrayUtil.xor(baseNonce, seqBytes);
		}

		@Override
		public void destroy() {
			Destroyables.destroyQuietly(key);
		}

		@Override
		public void close() {
			destroy();
		}
	}

}
