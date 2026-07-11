# A modern, minimal, fluent JOSE library.

> [!IMPORTANT]  
> We use this library to explore new additions to the JOSE standard, such as HPKE and post-quantum encryption.
> 
> The API is subject to change, and the library is not intended for production use yet.

## Implemented Specifications

- [RFC 7516 (JWE)](https://datatracker.ietf.org/doc/html/rfc7516) and [RFC 7518 (JWA)](https://datatracker.ietf.org/doc/html/rfc7518): compact and JSON serialization, `PBES2-*`, `ECDH-ES+A256KW`, `A128GCM`/`A256GCM`
- [draft-ietf-jose-hpke-encrypt](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/): use of HPKE ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) / [draft-ietf-hpke-hpke](https://datatracker.ietf.org/doc/draft-ietf-hpke-hpke/)) with JWE, in both Key Management Modes —
  Integrated Encryption (`HPKE-0`, `HPKE-1`, `HPKE-2`) and Key Encryption (`HPKE-0-KE`, `HPKE-1-KE`, `HPKE-2-KE`)
- [draft-ietf-jose-hpke-pq-pqt](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-pq-pqt/): PQ/T hybrid HPKE — `HPKE-9` and `HPKE-9-KE`, based on the MLKEM768-X25519 KEM and SHAKE256 KDF from [draft-ietf-hpke-pq](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/); the KEM is identical to X-Wing ([draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/))
- [RFC 9964 (AKP JWKs)](https://www.rfc-editor.org/rfc/rfc9964): parsing Algorithm Key Pair JWKs for the PQ/T hybrid algorithms

## Usage Examples:

### Integrated Encryption with quantum-secure HPKE-9 (MLKEM768-X25519, [a.k.a. X-Wing](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-concrete-hybrid-kems-04#section-4.2))

HPKE encrypts the payload directly — no separate content encryption algorithm involved:

```java
// encrypt:
var encrypted = JWE.build("payload")
		.encrypt(Alg.hpke9(receiverPublicKey))
		.toCompactSerialization();

// decrypt:
var decrypted = JWE.parse(encrypted).decrypt(Alg.hpke9(receiverPrivateKey));
```

### Key Encryption with HPKE-9-KE

HPKE encrypts a content encryption key, which then encrypts the payload:

```java
// encrypt:
var encrypted = JWE.build("payload")
		.encrypt(Enc.A256GCM, Alg.hpke9Ke(receiverPublicKey))
		.toCompactSerialization();

// decrypt:
var decrypted = JWE.parse(encrypted).decrypt(Alg.hpke9Ke(receiverPrivateKey));
```

### Multiple recipients

Key Encryption allows multiple recipients with different algorithms sharing one content encryption key:

```java
// encrypt with multiple recipients:
var encrypted = JWE.build("payload")
        .encrypt(Enc.A256GCM, Alg.pbes2("password".toCharArray(), 1000000), Alg.hpke9Ke(receiverPublicKey2))
        .toJsonSerialization();

// decrypt as recipient 1 (PBES2):
var decrypted1 = JWE.parse(encrypted).decrypt(Alg.pbes2("password".toCharArray()));

// decrypt as recipient 2 (HPKE-9-KE):
var decrypted2 = JWE.parse(encrypted).decrypt(Alg.hpke9Ke(receiverPrivateKey2));
```

## License
Distributed under the [MIT License](LICENSE).
