# A modern, minimal, fluent JOSE library.

> [!IMPORTANT]  
> We use this library to explore new additions to the JOSE standard, such as HPKE and post-quantum encryption.
> 
> The API is subject to change, and the library is not intended for production use yet.

## Implemented Specifications

- [RFC 7516 (JWE)](https://datatracker.ietf.org/doc/html/rfc7516) and [RFC 7518 (JWA)](https://datatracker.ietf.org/doc/html/rfc7518): compact and JSON serialization, `PBES2-*`, `ECDH-ES+A256KW`, `A128GCM`/`A256GCM`
- [draft-ietf-jose-hpke-encrypt](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/): use of HPKE ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) / [draft-ietf-hpke-hpke](https://datatracker.ietf.org/doc/draft-ietf-hpke-hpke/)) with JWE — ciphersuites `HPKE-0`, `HPKE-1`, `HPKE-2`
- [draft-ietf-jose-hpke-pq-pqt](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-pq-pqt/): PQ/T hybrid HPKE — ciphersuite `HPKE-9`, based on the MLKEM768-X25519 KEM and SHAKE256 KDF from [draft-ietf-hpke-pq](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/); the KEM is identical to X-Wing ([draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/))

## Usage Examples:

### Encrypt with quantum-secure HPKE-9 (MLKEM768-X25519, a.k.a. X-Wing)
```java
// encrypt with HPKE-9 (X-Wing):
var encrypted = JWE.build("payload")
		.encrypt(Enc.A256GCM, Alg.hpke9(receiverPublicKey))
		.toCompactSerialization();

// decrypt:
var decrypted = JWE.parse(encrypted).decrypt(Alg.hpke9(receiverPrivateKey));
```

### Encrypt with HPKE-2 (ECDH-ES)
```java
// encrypt with HPKE-2 (ECDH-ES):
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
