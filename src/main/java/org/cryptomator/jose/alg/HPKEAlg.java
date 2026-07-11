package org.cryptomator.jose.alg;

import com.google.gson.JsonObject;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.hpke.AEAD;
import org.cryptomator.jose.hpke.Kdf;
import org.cryptomator.jose.util.ArrayUtil;
import org.cryptomator.jose.util.Destroyables;

import javax.crypto.AEADBadTagException;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;


/// Perform HPKE
/// Key Encryption with [HPKE-2](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/)
/// Test vectors from [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180#name-dhkemp-521-hkdf-sha512-hkdf)
abstract sealed class HPKEAlg extends AbstractAlg permits HPKE0Alg, HPKE1Alg, HPKE2Alg, HPKE9Alg {

	private final PublicKey publicKey;
	private final PrivateKey privateKey;
	private final KEM kem;
	private final Kdf kdf;
	private final AEAD aead;

	public HPKEAlg(KEM kem, Kdf kdf, AEAD aead, PublicKey publicKey, PrivateKey privateKey) {
		this.kem = kem;
		this.kdf = kdf;
		this.aead = aead;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	@Override
	public byte[] decrypt(JsonObject combinedHeader, byte[] encryptedKey) throws JoseDecryptException {
		// https://www.rfc-editor.org/rfc/rfc9180#section-5.1.1-4
		if (!combinedHeader.has("ek")) {
			throw new JoseDecryptException("Missing ek header");
		}
		byte[] enc;
		try {
			enc = Base64.getUrlDecoder().decode(combinedHeader.get("ek").getAsString());
		} catch (IllegalArgumentException e) {
			throw new JoseDecryptException("Invalid base64 encoding", e);
		}
		SecretKey sharedSecret;
		try {
			sharedSecret = decap(enc, privateKey);
		} catch (DecapsulateException e) {
			throw new DecryptKeyException("Failed to decapsulate 'ek'", e);
		}

		Context ctx;
		try {
			ctx = keySchedule((byte) 0x00, sharedSecret, new byte[0], new byte[0], new byte[0]); // empty info, empty psk, empty pskId
		} finally {
			Destroyables.destroyQuietly(sharedSecret);
		}

		// https://www.rfc-editor.org/rfc/rfc9180#section-6.1-2
		try {
			return ctx.open(new byte[0], encryptedKey);
		} catch (AEADBadTagException e) {
			throw new DecryptKeyException("Failed to decrypt CEK", e);
		} finally {
			Destroyables.destroyQuietly(ctx);
		}
	}

	protected SecretKey decap(byte[] enc, PrivateKey privateKey) throws DecapsulateException {
		try {
			var receiver = kem.newDecapsulator(privateKey);
			return receiver.decapsulate(enc);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Invalid receiver public key for " + kem.getAlgorithm(), e);
		}
	}

	@Override
	public EncryptionResult encrypt(JsonObject combinedHeader, byte[] cek) {
		// https://www.rfc-editor.org/rfc/rfc9180#section-5.1.1-4
		var encapsulated = encap(publicKey);
		var enc = encapsulated.encapsulation();
		var sharedSecret = encapsulated.key();

		Context ctx;
		try {
			// The HPKE info parameter defaults to the empty string; mutually known private information MAY be used instead.
			// The HPKE AAD parameter MUST be set to the empty string.
			ctx = keySchedule((byte) 0x00, sharedSecret, new byte[0], new byte[0], new byte[0]); // empty info, empty psk, empty pskId
		} finally {
			Destroyables.destroyQuietly(sharedSecret);
		}

		// https://www.rfc-editor.org/rfc/rfc9180#section-6.1-2
		byte[] ct;
		try {
			ct = ctx.seal(new byte[0], cek); // empty aad
		} finally {
			Destroyables.destroyQuietly(ctx);
		}

		var perRecipientHeader = new JsonObject();
		perRecipientHeader.addProperty("ek", Base64.getUrlEncoder().encodeToString(enc));
		perRecipientHeader.addProperty("alg", name());
		return new EncryptionResult(ct, perRecipientHeader);
	}

	protected KEM.Encapsulated encap(PublicKey publicKey) {
		try {
			var sender = kem.newEncapsulator(publicKey);
			return sender.encapsulate();
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Invalid receiver public key for " + kem.getAlgorithm(), e);
		}
	}

	/// The `suite_id` value used within `LabeledExtract` and `LabeledExpand` as defined in [RFC 9180, Section 5.1](https://www.rfc-editor.org/rfc/rfc9180#section-5.1-8)
	protected abstract byte[] hpkeSuiteId();

	/// creates an encryption context as defined in [RFC 9180, Section 5.1](https://www.rfc-editor.org/rfc/rfc9180#section-5.1)
	///
	/// @param mode A one-byte value indicating the HPKE mode, defined in Table 1.
	/// @param sharedSecret A KEM shared secret generated for this transaction.
	/// @param info Application-supplied information (optional).
	/// @param psk A pre-shared key (PSK) held by both the sender and the recipient (optional).
	/// @param pskId: An identifier for the PSK (optional).
	// visible for testing
	Context keySchedule(byte mode, SecretKey sharedSecret, byte[] info, byte[] psk, byte[] pskId) {
		if ((psk.length == 0) != (pskId.length == 0)) {
			throw new IllegalArgumentException("Inconsistent PSK inputs");
		}
		if (mode == 0x00 && psk.length > 0) { // mode_base
			throw new IllegalArgumentException("PSK input provided when not needed");
		}
//		if (mode == 0x01 && psk.length == 0) { // mode_psk
//			throw new IllegalArgumentException("Missing required PSK input");
//		}
		if (mode != 0x00) {
			throw new UnsupportedOperationException("Only mode_base is currently supported");
		}

		var derived = kdf.combineSecrets(mode, sharedSecret, info, psk, pskId, hpkeSuiteId(), "AES", aead.nk, aead.nn);
		return new Context(derived.key(), derived.baseNonce()); // FIXME: what about ContextR?
	}

	// visible for testing
	class Context implements Destroyable {
		private final SecretKey key;
		private final byte[] baseNonce;
		private int sequence = 0;

		public Context(SecretKey key, byte[] baseNonce) {
			this.key = key;
			this.baseNonce = baseNonce;
		}

		public byte[] seal(byte[] aad, byte[] pt) {
			// https://www.rfc-editor.org/rfc/rfc9180#section-5.2-8
			try {
				return aead.seal(this.key, this.computeNonce(), aad, pt);
			} finally {
				sequence++;
			}
		}

		public byte[] open(byte[] aad, byte[] ct) throws AEADBadTagException {
			// https://www.rfc-editor.org/rfc/rfc9180#section-5.2-10
			try {
				return aead.open(this.key, this.computeNonce(), aad, ct);
			} finally {
				sequence++;
			}
		}

		private byte[] computeNonce() {
			// https://www.rfc-editor.org/rfc/rfc9180#section-5.2-12
			var seqBytes = new byte[aead.nn];
			var seqBuf = ByteBuffer.wrap(seqBytes);
			seqBuf.putInt(seqBytes.length - Integer.BYTES, sequence);
			return ArrayUtil.xor(baseNonce, seqBytes);
		}

		@Override
		public void destroy() {
			Destroyables.destroyQuietly(key);
		}
	}

}
