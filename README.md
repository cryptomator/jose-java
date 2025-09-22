# A modern, minimal, fluent JOSE library.

> [!IMPORTANT]  
> We use this library to explore new additions to the JOSE standard, such as HPKE and post-quantum encrypryption.
> 
> The API is subject to change, and the library is not intended for production use yet.

## Usage Examples:

### Encrypt with quantum-secure HPKE-7 (X-Wing)
```java
// encrpyt with HPKE-7 (X-Wing):
var encrypted = JWE.build("payload")
		.encrypt(Enc.A256GCM, Alg.hpke7(receiverPublicKey))
		.toCompactSerialization();

// decrypt:
var decrypted = JWE.parse(encrypted).decrypt(Alg.hpke7(receiverPrivateKey));
```

### Encrypt with HPKE-2 (ECDH-ES)
```java
// encrpyt with HPKE-2 (ECDH-ES):
var encrypted = JWE.build("payload")
		.encrypt(Enc.A256GCM, Alg.hpke2(receiverPublicKey))
		.toCompactSerialization();

// decrypt:
var decrypted = JWE.parse(encrypted).decrypt(Alg.hpke2(receiverPrivateKey));
```

### Multiple recipients
```java
// encrypt with multiple recipients:
var encrypted = JWE.build("payload")
        .encrypt(Enc.A256GCM, Alg.pbes2("password", 1000000), Alg.hpke2(receiverPublicKey2))
        .toJsonSerialization();

// decrypt as recipient 1 (PBES2):
var decrypted1 = JWE.parse(encrypted).decrypt(Alg.pbes2("password"));

// decrypt as recipient 2 (HPKE-2):
var decrypted2 = JWE.parse(encrypted).decrypt(Alg.hpke2(receiverPrivateKey2));
```

## License
Distributed under the [MIT License](LICENSE).
