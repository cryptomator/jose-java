package org.cryptomator.jose.hpke;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

class XwingKEMSpiTest {

	private KeyPairGenerator kpGen;
	private KEM kem;

	@BeforeEach
	void setup() throws NoSuchAlgorithmException {
		kpGen = KeyPairGenerator.getInstance("X-Wing", XwingProvider.INSTANCE);
		kem = KEM.getInstance("X-Wing", XwingProvider.INSTANCE);
	}

	@Test
	@DisplayName("Test randomized encapsulation and decapsulation")
	public void testEncapsulateAndDecapsulate() throws InvalidKeyException, DecapsulateException {
		var keyPair = kpGen.generateKeyPair();
		var enc = kem.newEncapsulator(keyPair.getPublic());
		var encapsulated = enc.encapsulate();

		var dec = kem.newDecapsulator(keyPair.getPrivate());
		var decapsulated = dec.decapsulate(encapsulated.encapsulation());

		Assertions.assertArrayEquals(encapsulated.key().getEncoded(), decapsulated.getEncoded());
	}

	@Test
	@DisplayName("Test derandomized encapsulation")
	// test vectors from https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-07#appendix-C
	public void testEncapsDerand() throws InvalidKeyException {
		var pk = Base64.getDecoder().decode("4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE/wUsrWxnPw9pfoaksSfJVE+D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx/kt/qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ+m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO/rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN+oOE9cOSqeGhto5ioOXwI6vloghE/5Pe61NpAsFAeHHU+/nMFPIcBToZhwzCZr+i+3kFKWxqifYOSs+Ex6acMEFWHgkDK0PQNX+PN+FI26tl+KpdEg2OygIyq/VFs0lBSxcNiVDwlF+Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU+2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF+1Vgn6Cso6CZlqGoU+9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S+UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb+Uv7tikh+FERiptupNyj1ALb/xJ5RVWnvJf7Rev9SBQc2glNSWGD1i+O+YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14+WH7gxn0ogNbyQH+3pwcSuDjeuWxde/K0S89gOMy+M/vPUaVKWE/pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6+wrXjh8ipiP3CO+ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS+6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt/lDiuQGXtNNc9SG8/UvkPCAfciN/djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS+fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd/UToFvNmcHzRlg7sFKXehChKt/HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn/QcnN/qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj/C/TXgMrlCfsiwlaRQZP/c0kEJYEjfVIoKIJO4739B/sD8flC0uoXn+ci8GzAPeW2mFntsG7/OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA==");
		var eseed = Base64.getDecoder().decode("PLHuqYgAS5MQPPsK7v0qaG4B+kpY6KNjnKih4/muV+I1uMyHPCPcYrjSYBaa+i91q5FqWNl0kYg10l5qQ1CFsg==");
		var publicKey = new XwingPublicKey(pk);
		var random = Mockito.mock(SecureRandom.class);
		Mockito.doAnswer(invocation -> {
			byte[] bytes = invocation.getArgument(0);
			Assertions.assertEquals(32, bytes.length);
			System.arraycopy(eseed, 0, bytes, 0, 32);
			return null;
		}).doAnswer(invocation -> {
			byte[] bytes = invocation.getArgument(0);
			Assertions.assertEquals(32, bytes.length);
			System.arraycopy(eseed, 32, bytes, 0, 32);
			return null;
		}).when(random).nextBytes(Mockito.any());
		var enc = kem.newEncapsulator(publicKey, random);
		var encapsulated = enc.encapsulate();

		var expectedCt = Base64.getDecoder().decode("uDqoKNTWK5qDzv/h09O7HvMSZGQ8BwxXmJJ+QfsHkUonP4+W54Js1TdaKD19qIUwTF3gUWoPBlQkPcW5f4v+uDH2glEhmqvdcjvGUSBBrLrvivRCZVJJQrkC5o/9IyIc2nCxtV13apLRFD6joMR19j7miQFXxxFtrj9iv3L2Cs0ruMwxziug3jZPUrjtOMedcZcVljpd04QtjotDq3BOR1m1MnvwJ8Y8j6hXxJCNWop7iKx/K+OU2Tw3Bt3U5pjMbONwEB9NAhMlQji0ouiCG25BShzyD2wSRLaZBG9aAcqgoaVVFjALQNIEjHfMc6+6ea/uqdLAEYvfKtuIcNwyjFUWzEWxogWBQQOeLJChEKnhazGN+1O9SaEm1rc/IVeHUXuJF8wByr0QfQaFmFTui0+YYcIm03ZMhzOasWw2Z9L0k4TlVFbdQEFLcKavhBWF9MkMaHJdV3BO6O585uL5vlgtvumF4Dj/w0br+04iFYtshDdKmrSkTh+R3lqsUZf4m8XlRC9R+aWTexAro76uv24cWDgKSl/tzkpOUCb4j1KPWf/S20F1Kzo9kO+r5GOJm31AhwxTDIhB6HErczZo7QM62/r7LUnTekTUBk5YY+sK8KCNR7PMiINzvAX3ozuEG8JYfFfraVVOijdnt1BpF7a3BJhyfxbqwaNuyNjPr3UVSfInfbJ36KVamlEGsjoCBrRyH6mzBIVSxb1bWU1uJH84wYxZGup/ViSccs57EXr8w6hiFYL5z3F4fhg97gk2eXbphAmtkhekl9+IgEI4TXcHprePX3+4QJ47U1F1NzRht3YALXmcutYoYL5wVz7L4Tskbg2n6TpSFo4Ptql1a4le9/AUeg3IG/pkSwiKkigWDA+azxN5opQc0owG68gOROF6ovgXcBCv14qXzgho0WKeuylMUVGBLFg9rriGhSIPTakRgRLgcEH8wk1VZKmf294ohp/gciOH16mk0W4cyFVZF+CZRKpeuqrsLPYmk6+tQqP1GPzmfSc8xsn7VHKzgOhXPsfeBqO6L9X5MdcltJMCbLCsvT/mLQDkx5DZZdegOjwLQiK6jCqaFuKsZY9XKuDnRur8T+ugI1dvCJQieKBB+4KnClldW6y/KXziApiYpx5cOw0cYii0hbGt5QmzX7yn7Kl7ITLny2vEZTdRRrfc6slpMIrAwqyJ54Y+uJQwFbJDFMr7nHwOhf5UPVZljCE2Mlme+r/B7EndjIhUe7LMQMnTjL0wmbRUeEBWBTHQGIzR6cI6Dr7goD1Vd9ZrHSvLS6ryHMf+8eA4BsqWKZ3w37xW4bK0Pk/CDDf4NMSvYhJ+fa6Gw8JaL2lqyLWJ3scdWVv76Ute1LwH2ACzMHlv2ontt3vgKUE2E5NU64zTdZFXj5xgDdm+jsYhn91Qet8zl+1NaHB7jROyTOTNj7IoUb/p1jJAfzHtb3yxYA3lbxdXZ0DOKjL8UUUDAUXPuX5j4OQdNUJ0oHnT5vsuFQ==");
		var expectedSs = Base64.getDecoder().decode("0t8FIhKPCd2OLJKx6QXHk9j1elTD2iWGHxC/TKYT44Q=");

		Mockito.verify(random, Mockito.times(2)).nextBytes(Mockito.any());

		Assertions.assertArrayEquals(expectedCt, encapsulated.encapsulation());
		Assertions.assertArrayEquals(expectedSs, encapsulated.key().getEncoded());
	}

}