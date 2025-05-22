package org.cryptomator.jose.alg;

import com.google.gson.JsonObject;
import org.cryptomator.jose.JoseDecryptException;
import org.cryptomator.jose.enc.DecryptCiphertextException;
import org.cryptomator.jose.hpke.AEAD;
import org.cryptomator.jose.hpke.HKDF;
import org.cryptomator.jose.util.ArrayUtil;
import org.cryptomator.jose.util.Curve;
import org.cryptomator.jose.util.Destroyables;

import javax.crypto.AEADBadTagException;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import javax.security.auth.Destroyable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;


/// Perform HPKE
/// Key Encryption with [HPKE-2](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt/)
/// Test vectors from [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180#name-dhkemp-521-hkdf-sha512-hkdf)
abstract sealed class HPKEAlg extends AbstractAlg permits HPKE0Alg, HPKE1Alg, HPKE2Alg {

	private final PublicKey publicKey;
	private final PrivateKey privateKey;
	private final KEM kem;
	private final HKDF kdf;
	private final AEAD aead;

	public HPKEAlg(KEM kem, HKDF kdf, AEAD aead, ECPublicKey publicKey, ECPrivateKey privateKey) {
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

		var pskIdHash = kdf.deriveData(labeledExtract("psk_id_hash").addIKM(pskId).extractOnly());
		var infoHash = kdf.deriveData(labeledExtract("info_hash").addIKM(info).extractOnly());
		var keyScheduleContext = ArrayUtil.concat(new byte[]{mode}, pskIdHash, infoHash);
		var secret = labeledExtract("secret").addIKM(psk).addSalt(sharedSecret);
		var key = kdf.deriveKey(labeledExpand(secret, "key", keyScheduleContext, aead.nk), "AES");
		var baseNonce = kdf.deriveData(labeledExpand(secret, "base_nonce", keyScheduleContext, aead.nn));
		// unused var exporterSecret = kdf.extractAndExpand(labeledExpand(secret, "exp", keyScheduleContext, 32); // get Nh from KDF enum https://www.iana.org/assignments/hpke/hpke.xhtml

		return new Context(key, baseNonce); // FIXME: what about ContextR?
	}

	private HKDFParameterSpec.Builder labeledExtract(String label) {
		return HKDFParameterSpec.ofExtract()
				.addIKM(new byte[]{'H', 'P', 'K', 'E', '-', 'v', '1'}) // TODO make constant
				.addIKM(hpkeSuiteId())
				.addIKM(label.getBytes(StandardCharsets.US_ASCII));
	}

	private HKDFParameterSpec.ExtractThenExpand labeledExpand(HKDFParameterSpec.Builder builder, String label, byte[] info, int length) {
		byte[] labeledInfo = labeledInfo(hpkeSuiteId(), label, info, length);
		return builder.thenExpand(labeledInfo, length);
	}

	private static byte[] labeledInfo(byte[] suiteId, String label, byte[] info, int length) {
		byte[] l = { (byte) (length >> 8), (byte) length }; // TODO: or (length >>> 8)?
		return ArrayUtil.concat(l, "HPKE-v1".getBytes(StandardCharsets.US_ASCII), suiteId, label.getBytes(StandardCharsets.US_ASCII), info);
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
