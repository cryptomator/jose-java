package org.cryptomator.jose.hpke;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.cryptomator.jose.util.ArrayUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/// Single-stage XOF-based KDFs as defined in [draft-ietf-hpke-pq, Section 5](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05#section-5),
/// where `Derive(ikm, L) = SHAKE<SIZE>(M = ikm, d = 8*L)`.
public enum Shake implements Kdf {

	/// SHAKE256, KDF ID `0x0011`, `Nh` = 64
	SHAKE256(256, 64);

	private static final byte[] HPKE_V1 = "HPKE-v1".getBytes(StandardCharsets.US_ASCII);

	private final int bitLength;
	private final int nh; // Nh

	Shake(int bitLength, int nh) {
		this.bitLength = bitLength;
		this.nh = nh;
	}

	@Override
	public DerivedKeys combineSecrets(byte mode, SecretKey sharedSecret, byte[] info, byte[] psk, byte[] pskId, byte[] suiteId, String keyAlg, int nk, int nn) {
		// https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.1 (CombineSecrets_OneStage)
		var sharedSecretBytes = sharedSecret.getEncoded();
		if (sharedSecretBytes == null) {
			throw new IllegalArgumentException("Shared secret is not extractable");
		}
		var prefixedSharedSecret = new byte[0];
		var secrets = new byte[0];
		var context = new byte[0];
		var secret = new byte[0];
		try {
			prefixedSharedSecret = lengthPrefixed(sharedSecretBytes);
			secrets = ArrayUtil.concat(lengthPrefixed(psk), prefixedSharedSecret);
			context = ArrayUtil.concat(new byte[]{mode}, lengthPrefixed(pskId), lengthPrefixed(info));
			secret = labeledDerive(suiteId, secrets, "secret", context, nk + nn + nh);
			var key = new SecretKeySpec(secret, 0, nk, keyAlg);
			var baseNonce = Arrays.copyOfRange(secret, nk, nk + nn);
			return new DerivedKeys(key, baseNonce); // exporter_secret (secret[nk + nn:]) is unused
		} finally {
			Arrays.fill(sharedSecretBytes, (byte) 0x00);
			Arrays.fill(prefixedSharedSecret, (byte) 0x00);
			Arrays.fill(secrets, (byte) 0x00);
			Arrays.fill(secret, (byte) 0x00);
		}
	}

	/// `LabeledDerive` for one-stage KDFs as defined in [draft-ietf-hpke-hpke, Section 4.4](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-4.4)
	// visible for testing
	byte[] labeledDerive(byte[] suiteId, byte[] ikm, String label, byte[] context, int length) {
		var labeledIkm = ArrayUtil.concat(ikm, HPKE_V1, suiteId, lengthPrefixed(label.getBytes(StandardCharsets.US_ASCII)), i2osp2(length), context);
		try {
			var digest = new SHAKEDigest(bitLength);
			digest.update(labeledIkm, 0, labeledIkm.length);
			var result = new byte[length];
			digest.doFinal(result, 0, length);
			return result;
		} finally {
			Arrays.fill(labeledIkm, (byte) 0x00);
		}
	}

	// lengthPrefixed(x) = concat(I2OSP(len(x), 2), x)
	private static byte[] lengthPrefixed(byte[] x) {
		return ArrayUtil.concat(i2osp2(x.length), x);
	}

	private static byte[] i2osp2(int i) {
		return new byte[]{(byte) (i >>> 8), (byte) i};
	}

}
