import org.jspecify.annotations.NullMarked;

@NullMarked
module org.cryptomator.jose {
	requires transitive com.google.gson;
	requires transitive org.jspecify;
	requires org.bouncycastle.provider;

	exports org.cryptomator.jose;
	exports org.cryptomator.jose.jwe;
	exports org.cryptomator.jose.jws;

	exports org.cryptomator.jose.hpke to java.base;
	// provides Provider with org.cryptomator.jose.hpke.XwingProvider; // only required, if we want to find the provider by name
}
