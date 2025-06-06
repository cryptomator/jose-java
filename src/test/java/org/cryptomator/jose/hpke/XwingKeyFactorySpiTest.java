package org.cryptomator.jose.hpke;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

class XwingKeyFactorySpiTest {


	private KeyFactory keyFactory;
	private KeyPair keyPair;

	@BeforeEach
	public void setup() throws NoSuchAlgorithmException {
		// test vectors from https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-07#appendix-C
		var seed = Base64.getDecoder().decode("f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY=");
		keyPair = XwingKeyPairGeneratorSpi.generateKeyPairDerand(seed);
		keyFactory = KeyFactory.getInstance("X-Wing", XwingProvider.INSTANCE);
	}

	@Nested
	public class X509 {

		private X509EncodedKeySpec bcEncoded;

		@BeforeEach
		public void setup() throws IOException {
			AlgorithmIdentifier algId = new AlgorithmIdentifier(ASN1ObjectIdentifier.tryFromID("1.3.6.1.4.1.62253.25722"));
			SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, keyPair.getPublic().getEncoded());
			bcEncoded = new X509EncodedKeySpec(spki.getEncoded());
		}

		@Test
		public void testEncode() throws InvalidKeySpecException {
			var keySpec = keyFactory.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class);

			Assertions.assertArrayEquals(bcEncoded.getEncoded(), keySpec.getEncoded());
		}

		@Test
		public void testDecode() throws InvalidKeySpecException {
			var key = keyFactory.generatePublic(bcEncoded);

			Assertions.assertArrayEquals(keyPair.getPublic().getEncoded(), key.getEncoded());
		}

		@Test
		public void testTranslate() throws InvalidKeyException {
			var alienX509Key = Mockito.mock(PublicKey.class);
			Mockito.doReturn("X-Wing").when(alienX509Key).getAlgorithm();
			Mockito.doReturn(bcEncoded.getEncoded()).when(alienX509Key).getEncoded();
			Mockito.doReturn("X.509").when(alienX509Key).getFormat();

			var key = keyFactory.translateKey(alienX509Key);

			Assertions.assertArrayEquals(keyPair.getPublic().getEncoded(), key.getEncoded());
		}

	}

	@Nested
	public class PKCS8 {

		private PKCS8EncodedKeySpec bcEncoded;

		@BeforeEach
		public void setup() throws IOException {
			AlgorithmIdentifier algId = new AlgorithmIdentifier(ASN1ObjectIdentifier.tryFromID("1.3.6.1.4.1.62253.25722"));
			PrivateKeyInfo pkInfo = new PrivateKeyInfo(algId, keyPair.getPrivate().getEncoded());
			bcEncoded = new PKCS8EncodedKeySpec(pkInfo.getEncoded());
		}

		@Test
		public void testEncode() throws InvalidKeySpecException {
			var keySpec = keyFactory.getKeySpec(keyPair.getPrivate(), PKCS8EncodedKeySpec.class);

			Assertions.assertArrayEquals(bcEncoded.getEncoded(), keySpec.getEncoded());
		}

		@Test
		public void testDecode() throws InvalidKeySpecException {
			var key = keyFactory.generatePrivate(bcEncoded);

			Assertions.assertArrayEquals(keyPair.getPrivate().getEncoded(), key.getEncoded());
		}

		@Test
		public void testDecodeWithOptionalAttributes() throws InvalidKeySpecException, IOException {
			AlgorithmIdentifier algId = new AlgorithmIdentifier(ASN1ObjectIdentifier.tryFromID("1.3.6.1.4.1.62253.25722"));
			ASN1Set attr = new BERSet(new ASN1Encodable[]{algId, algId, algId, algId, algId, algId, algId, algId, algId, algId, algId, algId, algId, algId, algId, algId, algId, algId, algId});
			PrivateKeyInfo pkInfo = new PrivateKeyInfo(algId, keyPair.getPrivate().getEncoded(), attr);
			bcEncoded = new PKCS8EncodedKeySpec(pkInfo.getEncoded());

			var key = keyFactory.generatePrivate(bcEncoded);

			Assertions.assertArrayEquals(keyPair.getPrivate().getEncoded(), key.getEncoded());
		}

		@Test
		public void testTranslate() throws InvalidKeyException {
			var alienPKCSKey = Mockito.mock(PrivateKey.class);
			Mockito.doReturn("X-Wing").when(alienPKCSKey).getAlgorithm();
			Mockito.doReturn(bcEncoded.getEncoded()).when(alienPKCSKey).getEncoded();
			Mockito.doReturn("PKCS#8").when(alienPKCSKey).getFormat();

			var key = keyFactory.translateKey(alienPKCSKey);

			Assertions.assertArrayEquals(keyPair.getPrivate().getEncoded(), key.getEncoded());
		}

	}

}