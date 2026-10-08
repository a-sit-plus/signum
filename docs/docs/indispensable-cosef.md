![indispensable-cosef](assets/cosef-dark-large.png#only-light) ![indispensable-cosef](assets/cosef-light-large.png#only-dark)

[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus.signum/indispensable-cosef?label=maven-central)](https://mvnrepository.com/artifact/at.asitplus.signum.indispensable-cosef/)

# Indispensable COSE Data Structures

This [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) library provides platform-independent COSE data
types and utility functions. It comes with predefined COSE algorithm identifiers and guaranteed correct
serialization, leveraging kotlinx.serialization.
There's really not much more to it; it's data structures with self-describing names that interop with
_Indispensable_ data classes such as `SignatureAlgorithm`, `CryptoSignature`,  and `CryptoPublicKey`.

The preconfigured serializer ensuring compliant serialization of COSE-related data structures is called `coseCompliantSerializer`. Serialization describes the wire format; it does not verify a signature or establish trust.

!!! tip
      **Do check out the full API docs [here](dokka/indispensable-cosef/index.html)** to get an overview about all COSE-specific data types included!


## Using it in your Projects

This library was built for [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html). Currently, it supports all KMP targets except `watchosDeviceArm64`.

Simply declare the desired dependency to get going:

Use `at.asitplus.signum:indispensable-cosef:4.0.0`.

## COSE Sign1

`CoseSigned` represents COSE_Sign1. Prepare the signature input, sign it, then use `create` so that
its `wireFormat` matches the header, payload and signature. The protected header is authenticated;
unprotected headers are not. Keep the external AAD agreed by both parties: it is authenticated but
is not transported inside the object.

```kotlin
--8<-- "indispensable-cosef/src/jvmTest/kotlin/at/asitplus/signum/examples/CoseExamples.kt:cose-sign-verify"
```

1. The verifier uses our independently trusted signer key. In a receiver, map the `kid` to a trusted key and enforce the allowed algorithm before verifying.

`CryptoSignature.coseBytes` supplies the appropriate wire encoding, including fixed-width P1363
for ECDSA. Raw byte-array payloads are carried as-is; other typed payloads use an encoded CBOR item
(tag 24). `ByteStringWrapper` payloads are rejected to avoid nested wrapping and type erasure.
The decoded wire representation preserves the bytes needed to reconstruct the signature input.

## CBOR Web Tokens

`CborWebToken` serializes the registered CWT claim labels:

```kotlin
--8<-- "indispensable-cosef/src/jvmTest/kotlin/at/asitplus/signum/examples/CoseExamples.kt:cose-cwt"
```

This is a serialization and claim-policy example. To authenticate a CWT, carry it in a signed or
MACed COSE object and verify that object first. Check issuer, audience, time and application-specific
claims separately. `CoseMac` and `CoseKey` provide the corresponding MAC and key data structures;
serialization alone does not authenticate either.
