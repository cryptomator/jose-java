# A modern, minimal, fluent JOSE library.

> [!IMPORTANT]  
> We use this library to explore new additions to the JOSE standard, such as HPKE and post-quantum encryption.
> 
> The API is subject to change, and the library is not intended for production use yet.

## Implemented Specifications

- [RFC 7516 (JWE)](https://datatracker.ietf.org/doc/html/rfc7516) and [RFC 7518 (JWA)](https://datatracker.ietf.org/doc/html/rfc7518): compact and JSON serialization (incl. multiple recipients with per-recipient headers), `A256KW`, `PBES2-HS512+A256KW`, `ECDH-ES+A256KW` (P-256/P-384/P-521), `A128GCM`/`A256GCM`
- [RFC 7515 (JWS)](https://datatracker.ietf.org/doc/html/rfc7515): compact serialization, `HS256`/`HS384`/`HS512`
- [draft-ietf-jose-hpke-encrypt](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/): use of HPKE ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) / [draft-ietf-hpke-hpke](https://datatracker.ietf.org/doc/draft-ietf-hpke-hpke/)) with JWE, in both Key Management Modes —
  Integrated Encryption (`HPKE-0`, `HPKE-1`, `HPKE-2`) and Key Encryption (`HPKE-0-KE`, `HPKE-1-KE`, `HPKE-2-KE`); HPKE `mode_base`, and `mode_psk` via `withPsk(psk)` (`psk_id` header parameter)
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

With a pre-shared key (HPKE `mode_psk`), the recipient additionally learns that the sender holds the PSK; the PSK identifier travels as the `psk_id` header parameter:

```java
var pskId = "our-little-secret".getBytes(StandardCharsets.UTF_8); 
var psk = new Psk(pskKey, pskId); // pskKey: a SecretKey with at least 32 bytes of entropy
var encrypted = JWE.build("payload").encrypt(Alg.hpke9(receiverPublicKey).withPsk(psk)).toCompactSerialization();
var decrypted = JWE.parse(encrypted).decrypt(Alg.hpke9(receiverPrivateKey).withPsk(psk)); // refuses tokens without psk_id
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

Key Encryption allows multiple recipients with different algorithms sharing one content encryption key. Since every recipient unwraps the same key, the JWE is only as strong as its weakest recipient (here: the password).

```java
// encrypt with multiple recipients:
char[] password = ...; // stays owned by the caller: the library never copies or wipes it
try {
    var encrypted = JWE.build("payload")
            .encrypt(Enc.A256GCM, Alg.pbes2(password), Alg.hpke9Ke(receiverPublicKey2))
            .toJsonSerialization();
} finally {
    Arrays.fill(password, '\0');
}

// decrypt as recipient 1 (PBES2):
var decrypted1 = JWE.parse(encrypted).decrypt(Alg.pbes2(password));

// decrypt as recipient 2 (HPKE-9-KE):
var decrypted2 = JWE.parse(encrypted).decrypt(Alg.hpke9Ke(receiverPrivateKey2));
```

### Per-recipient headers, `kid`-targeted decryption, critical extensions

Each recipient may carry its own header parameters, e.g. a `kid` and private parameters. The parser enforces `crit` (RFC 7516 §4.1.13): a JWE listing an extension the caller did not declare is rejected when parsing.

```java
// encrypt:
var encrypted = JWE.build("payload")
        .withProtectedHeader(header) // e.g. {"cty":"json","crit":["org.example.version"],"org.example.version":1}
        .encrypt(Enc.A256GCM,
                Recipient.withAlg(Alg.a256kw(kek)).withClaim("kid", "org.example.password").withClaim("org.example.iterations", 3),
                Recipient.withAlg(Alg.ecdhEs(recoveryPublicKey)).withClaim("kid", "org.example.recovery"))
        .toJsonSerialization();

// inspect, then decrypt the recipient identified by kid:
var parsed = JWE.parse(encrypted, "org.example.version");
var kids = parsed.recipientHeaders().stream().map(h -> h.get("kid").getAsString()).toList();
var decrypted = parsed.decrypt("org.example.recovery", Alg.ecdhEs(recoveryPrivateKey));
```

### JWS with HMAC

```java
// sign:
var token = JWS.build("{\"sub\":\"alice\"}")
        .withProtectedHeader(header) // e.g. {"typ":"JWT","kid":"masterkey"}
        .sign(MacAlg.hs256(key));

// verify:
var verified = JWS.parse(token).verify(MacAlg.hs256(key));
var payload = verified.payload();
```

`verify` checks the signature only. This library implements JWS, not JWT: if the payload is a JWT claims set, validating `exp`, `nbf`, `aud`, `iss` etc. is up to the caller.

## License
Distributed under the [MIT License](LICENSE).
