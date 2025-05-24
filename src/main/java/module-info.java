module org.cryptomator.jose {
	requires transitive com.google.gson;
	requires org.bouncycastle.provider;

	exports org.cryptomator.jose;
	exports org.cryptomator.jose.builder;
	exports org.cryptomator.jose.parser;

	// provides Provider with org.cryptomator.jose.hpke.XwingProvider; // only required, if we want to find the provider by name
}