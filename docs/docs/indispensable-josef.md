![indispensable-josef](assets/josef-dark-large.png#only-light) ![indispensable-josef](assets/josef-light-large.png#only-dark)

[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus.signum/indispensable-josef?label=maven-central)](https://mvnrepository.com/artifact/at.asitplus.signum.indispensable-josef/)

# Indispensable JOSE Data Structures

This [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) library provides platform-independent JOSE data
types and utility functions. It comes with predefined JOSE algorithm identifiers and guaranteed correct
serialization, leveraging kotlinx.serialization.
There's really not much more to it; it's data structures with self-describing names that interop with
_Indispensable_ data classes such as `SignatureAlgorithm`, `CryptoSignature`,  and `CryptoPublicKey`.

The preconfigured serializer ensuring compliant serialization of JOSE-related data structures is called `joseCompliantSerializer`. Serialization describes the wire format; it does not verify a signature or establish trust.

!!! tip
    **Do check out the full API docs [here](dokka/indispensable-josef/index.html)** to get an overview about all JOSE-specific data types included!

## Using it in your Projects

This library was built for [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html). Currently, it supports all KMP targets except `watchosDeviceArm64`.

Simply declare the desired dependency to get going:

Use `at.asitplus.signum:indispensable-josef:4.0.0`.

## JSON Web Keys

`JsonWebKey` describes a key, including optional metadata such as `kid`. Public keys convert to JWKs
and back. Receiving a JWK in a header tells you which key someone supplied; it does not make that key trusted.

```kotlin
--8<-- "indispensable-josef/src/jvmTest/kotlin/at/asitplus/signum/examples/JoseExamples.kt:jose-jwk"
```

## JSON Web Signatures

`JwsCompact` handles compact serialization. `JwsFlattened` and `JwsGeneral` handle the JSON
representations, including separate protected and unprotected header fragments (`JwsHeader.Part`).
The protected header is part of the signature input; an unprotected `kid` is only a lookup hint.
Header fragments must not define the same parameter twice. `JwsTyped` provides a typed payload view.

Here we pin ES256 and look up the key in an application-owned trusted map:

```kotlin
--8<-- "indispensable-josef/src/jvmTest/kotlin/at/asitplus/signum/examples/JoseExamples.kt:jose-jws-sign-verify"
```

1. This map is established independently of the incoming JWS. A header key or URL is not a trust decision.

The callback supplies JOSE signature bytes; ECDSA uses P1363, not the DER signature returned by many
native APIs. Verification returns `SignatureVerifier.Success` and throws on failure. Do not rebuild
the input from parsed JSON: verify the received encoded header and payload.

`JwsSigned` remains a deprecated compatibility API. Prefer the representation-specific APIs above
for new code; see the [migration guide](migration.md) for historical examples.

## JWT Claims

A JWT is a claims payload carried in a JWS. `JwtPayload` defines common claim properties; implementors
must supply their own `@SerialName` annotations (they are not inherited). The older `JsonWebToken`
class is deprecated. A plain JSON object also works when a typed model is unnecessary:

```kotlin
--8<-- "indispensable-josef/src/jvmTest/kotlin/at/asitplus/signum/examples/JoseExamples.kt:jose-jwt"
```

1. This fixed timestamp makes the claim-policy example repeatable. In an application, check the current time after successful signature verification.

Issuer, audience, expiration, not-before, replay protection and allowed algorithms are application
policy. Parsing a payload successfully proves none of them. Claims belong to the payload, not the JWS header.

### Typed Claims with `JwtPayload`

`JwtPayload` defines the seven registered JWT claim properties without requiring any of them.
`JwtClaimNames.IanaRegistered.ClaimNames.RFC7519` supplies the corresponding wire-name constants;
the catalogue also includes registered claims from other specifications and explicitly unregistered
claims. These names help describe a schema; they do not enforce its policy.

Implement the interface in your own serializable payload. Repeat `@SerialName` and the NumericDate
serializer on the implementing properties: annotations on the interface are not inherited.

```kotlin
--8<-- "indispensable-josef/src/jvmTest/kotlin/at/asitplus/signum/examples/JoseExamples.kt:jose-jwt-payload-model"
```

Here we sign and reopen a typed JWT, verify it with our trusted key, then enforce a small service
policy. The test also rejects the wrong audience, a future not-before time, and the exact expiration
boundary:

```kotlin
--8<-- "indispensable-josef/src/jvmTest/kotlin/at/asitplus/signum/examples/JoseExamples.kt:jose-jwt-typed-claims"
```

1. This policy requires issuer, audience, subject, not-before and expiration. Other applications may require different claims, clock-skew rules and replay protection; `jwtId` alone does not prevent replay.
