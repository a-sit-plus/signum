# Signum Examples

This page demonstrates how to accomplish common tasks using _Signum_. The snippets are extracted
from executed examples in their owning modules.

## Creating and Verifying a JSON Web Signature

This example requires _Supreme_ and _Indispensable Josef_. We pin the algorithm and obtain the
verification key from an independently trusted map:

```kotlin
--8<-- "indispensable-josef/src/jvmTest/kotlin/at/asitplus/signum/examples/JoseExamples.kt:jose-jws-sign-verify"
```

1. Trust is established by the application, not by a key supplied in an incoming header.

See [Indispensable Josef](indispensable-josef.md) for JWKs, header handling and JWT claim checks.

## Creating and Verifying a COSE Sign1 Object

This example requires _Supreme_ and _Indispensable Cosef_. Both parties agree on the external AAD:

```kotlin
--8<-- "indispensable-cosef/src/jvmTest/kotlin/at/asitplus/signum/examples/CoseExamples.kt:cose-sign-verify"
```

1. Use a trusted key and enforce the allowed algorithm before verifying an incoming object.

## Custom ASN.1 Structures

The ASN.1 engine, parser and tagged builder DSL live in [awesn1](https://github.com/a-sit-plus/awesn1).
See its manual for custom-tagged structures. Signum's [extensibility](extensibility.md) page describes
how semantic cryptographic types integrate with that engine.