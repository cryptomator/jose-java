package org.cryptomator.jose.hpke;

import org.cryptomator.jose.util.ArrayUtil;

import javax.crypto.KDF;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

/// Two-stage `Extract`/`Expand` KDF as defined in [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)
public record HKDF(KDF kdf) implements Kdf {

	public static HKDF sha256() {
		try {
			return new HKDF(KDF.getInstance("HKDF-SHA256"));
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("JVM doesn't support HKDF-SHA256", e);
		}
	}

	public static HKDF sha384() {
		try {
			return new HKDF(KDF.getInstance("HKDF-SHA384"));
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("JVM doesn't support HKDF-SHA384", e);
		}
	}

	public static HKDF sha512() {
		try {
			return new HKDF(KDF.getInstance("HKDF-SHA512"));
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("JVM doesn't support HKDF-SHA512", e);
		}
	}

	@Override
	public DerivedKeys combineSecrets(byte mode, SecretKey sharedSecret, byte[] info, byte[] psk, byte[] pskId, byte[] suiteId, String keyAlg, int nk, int nn) {
		// https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-5.1 (CombineSecrets_TwoStage)
		var pskIdHash = deriveData(labeledExtract(suiteId, "psk_id_hash").addIKM(pskId).extractOnly());
		var infoHash = deriveData(labeledExtract(suiteId, "info_hash").addIKM(info).extractOnly());
		var keyScheduleContext = ArrayUtil.concat(new byte[]{mode}, pskIdHash, infoHash);
		var secret = labeledExtract(suiteId, "secret").addIKM(psk).addSalt(sharedSecret);
		var key = deriveKey(labeledExpand(suiteId, secret, "key", keyScheduleContext, nk), keyAlg);
		var baseNonce = deriveData(labeledExpand(suiteId, secret, "base_nonce", keyScheduleContext, nn));
		// unused var exporterSecret = deriveData(labeledExpand(suiteId, secret, "exp", keyScheduleContext, nh)); // get Nh from KDF https://www.iana.org/assignments/hpke/hpke.xhtml
		return new DerivedKeys(key, baseNonce);
	}

	/// `LabeledExtract` for two-stage KDFs as defined in [draft-ietf-hpke-hpke, Section 4.4](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-4.4)
	private HKDFParameterSpec.Builder labeledExtract(byte[] suiteId, String label) {
		return HKDFParameterSpec.ofExtract()
				.addIKM(new byte[]{'H', 'P', 'K', 'E', '-', 'v', '1'})
				.addIKM(suiteId)
				.addIKM(label.getBytes(StandardCharsets.US_ASCII));
	}

	/// `LabeledExpand` for two-stage KDFs as defined in [draft-ietf-hpke-hpke, Section 4.4](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-03#section-4.4)
	private HKDFParameterSpec.ExtractThenExpand labeledExpand(byte[] suiteId, HKDFParameterSpec.Builder builder, String label, byte[] info, int length) {
		byte[] labeledInfo = labeledInfo(suiteId, label, info, length);
		return builder.thenExpand(labeledInfo, length);
	}

	private static byte[] labeledInfo(byte[] suiteId, String label, byte[] info, int length) {
		byte[] l = {(byte) (length >>> 8), (byte) length};
		return ArrayUtil.concat(l, "HPKE-v1".getBytes(StandardCharsets.US_ASCII), suiteId, label.getBytes(StandardCharsets.US_ASCII), info);
	}

	public SecretKey deriveKey(HKDFParameterSpec params, String alg) {
		try {
			return kdf.deriveKey(alg, params);
		} catch (InvalidAlgorithmParameterException e) {
			throw new IllegalArgumentException("invalid KDF params", e);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("Invalid key alg", e);
		}
	}

	public byte[] deriveData(HKDFParameterSpec params) {
		try {
			return kdf.deriveData(params);
		} catch (InvalidAlgorithmParameterException e) {
			throw new IllegalArgumentException("invalid KDF params", e);
		}
	}

}
